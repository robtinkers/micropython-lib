# http/client.py

import micropython, socket

HTTP_PORT = const(80)
HTTPS_PORT = const(443)

OK = const(200)
responses = {OK: "OK"}

# We always set the Content-Length header for these methods because some
# servers will otherwise respond with a 411
_METHODS_EXPECTING_BODY = frozenset({"PATCH", "POST", "PUT"})

_IMPORTANT_HEADERS = frozenset({
    b"connection",  # required
    b"content-encoding",
    b"content-length",  # required
    b"content-type",
    b"etag",
    b"keep-alive",  # required
    b"location",  # required
    b"retry-after",
    b"transfer-encoding",  # required
    b"www-authenticate",
})

_DECODE_HEAD = const("iso-8859-1")
_ENCODE_HEAD = const("iso-8859-1")
_DECODE_BODY = const("utf-8")
_ENCODE_BODY = const("utf-8")

@micropython.viper
def _has_C0_control(buf:ptr8, buflen:int) -> int:
    i = 0
    while i < buflen:
        if buf[i] < 32:
            return 1
        i += 1
    return 0

def encode_and_validate(b, *args):
    if isinstance(b, str):
        b = b.encode(*args)
    elif not isinstance(b, bytes):
        b = bytes(b)
    if _has_C0_control(b, len(b)) == 1:
        raise ValueError("can't contain control characters")
    return b

def isiterator(x):
    try:
        iter(x)
        return True
    except TypeError:
        return False

def create_connection(address, timeout=None):
    host, port = address
    for f, t, p, n, a in socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM):
        sock = None
        try:
            sock = socket.socket(f, t, p)
            try:
                if timeout != 0:  # 0 would be a non-blocking socket
                    sock.settimeout(timeout)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except (AttributeError, OSError):
                pass
            sock.connect(a)
            return sock
        except OSError:
            if sock is not None:
                sock.close()
    raise OSError("create_connection() failed")

# derived from CPython (all bugs are mine)
def parse_host_port(host, port):
    if port is None:
        i = host.rfind(':')
        j = host.rfind(']')         # ipv6 addresses have [...]
        if i > j:
            try:
                port = int(host[i+1:], 10)
            except ValueError:
                if host[i+1:] != "":
                    raise
            host = host[:i]
    if host and host[0] == '[' and host[-1] == ']':
        host = host[1:-1]
    return (host, port)

def parse_headers(sock, *, extra_headers=True, parse_cookies=None):  # returns dict/s {bytes:bytes, ...}
    # parse_cookies is tri-state:
    # parse_cookies == True? parse set-cookie headers and return as a dict
    # parse_cookies == False? don't parse set-cookie headers but return an empty dict
    # parse_cookies == None? don't parse set-cookie headers and don't even return a dict
    
    headers = {}
    if parse_cookies is not None:
        cookies = {}
    last_header = None
    
    while True:
        line = sock.readline()
        if not line or line == b"\r\n":
            if parse_cookies is not None:
                return headers, cookies
            else:
                return headers
        
        if line.startswith((b' ', b'\t')):
            if last_header is not None:
                headers[last_header] += b" " + line.strip()
            continue
        
        x = line.find(b':')
        if x == -1:
            continue
        key = line[:x].strip().lower()
        val = line[x+1:].strip()
        
        if key == b"set-cookie":
            if parse_cookies == True:
                x = val.find(b'=')
                if x != -1:
                    cookies[val[:x]] = val[x+1:]  # includes any quotes and parameters
        elif extra_headers == True or key in _IMPORTANT_HEADERS \
                or (isinstance(extra_headers, (frozenset, set, list, tuple)) and key in extra_headers):
            if key in headers:
                headers[key] += b", " + val
            else:
                headers[key] = val
            last_header = key
            continue
        
        last_header = None

class HTTPResponse:
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        return False
    
    def __init__(self, sock, debuglevel=0, method=None, url=None, *, extra_headers=False, parse_cookies=False):
        self._sock = sock
        self.debuglevel = debuglevel
        self._method = method
        self.url = url
        if parse_cookies is None:
            parse_cookies = False
        
        self.version, self.status, self.reason = self._read_status()
        if self.debuglevel > 0:
            print("status:", repr(self.version), repr(self.status), repr(self.reason))
        
        self.headers, self.cookies = parse_headers(self._sock, extra_headers=extra_headers, parse_cookies=parse_cookies)
        if self.debuglevel > 0:
            for key, val in self.headers.items():
                print("header:", repr(key), "=", repr(val))
            for key, val in self.cookies.items():
                print("cookie:", repr(key), "=", repr(val))
        
        # are we using the chunked-style of transfer encoding?
        self.chunked = b"chunked" in self.headers.get(b"transfer-encoding", b"").lower()
        self.chunk_left = None
        
        # will the connection close at the end of the response?
        if self.status == 101:
            self.will_close = True
        elif self.version == 11:
            self.will_close = b"close" in self.headers.get(b"connection", b"").lower()
        else:
            self.will_close = b"keep-alive" not in self.headers.get(b"connection", b"").lower() and self.headers.get(b"keep-alive") is None
        
        # do we have a Content-Length?
        # NOTE: RFC 2616, S4.4, #3 says we ignore this if chunked
        self.length = None
        length = self.headers.get(b"content-length")
        if length and not self.chunked:
            try:
                self.length = int(length, 10)
            except ValueError:
                pass  # self.length is already None
            else:
                if self.length < 0:  # ignore nonsensical negative lengths
                    self.length = None
        
        # does the body have a fixed length? (of zero)
        if (self.status == 204 or self.status == 304 or
            100 <= self.status < 200 or      # 1xx codes
            self._method == "HEAD"):
            self.length = 0
        
        # if the connection remains open, and we aren't using chunked, and
        # a content-length was not provided, then assume that the connection
        # WILL close.
        if (not self.will_close and
            not self.chunked and
            self.length is None):
            self.will_close = True
    
    def _read_status(self):
        # read until we get a non-100 response
        while True:
            line = self._sock.readline()
            if not line:
                raise RemoteDisconnected()
            if self.debuglevel > 0:
                print("status:", repr(line))
            
            if not line.startswith(b"HTTP/"):
                raise BadStatusLine()
            
            try:
                line = line.decode(_DECODE_HEAD).strip()
                line = line.split(None, 2)
                if len(line) == 3:
                    version, status, reason = line
                elif len(line) == 2:
                    version, status = line
                    reason = ""
                else:
                    raise BadStatusLine()
                status = int(status, 10)
            except (UnicodeError, ValueError):
                raise BadStatusLine()
            
            # The status code is a three-digit number
            if status < 100 or status > 999:
                raise BadStatusLine()
            
            if status != 100:
                break
            # skip the header from the 100 response
            while True:
                line = self._sock.readline()
                if not line or line == b"\r\n":
                    break
                if self.debuglevel > 0:
                    print("header:", repr(line))
        
        if version == "HTTP/1.0" or version == "HTTP/0.9":
            # Some servers might still return 0.9, treat it as 1.0 anyway
            version = 10
        elif version.startswith("HTTP/1."):
            version = 11  # use HTTP/1.1 code for HTTP/1.x where x>=1
        else:
            raise BadStatusLine()
        
        return version, status, reason
    
    def close(self):
        self._close(False)
    
    def _close(self, hard):
        if hard or self.will_close or self.chunk_left is not None or self.length != 0:
            if self._sock is not None:
                self._sock.close()
            self.chunk_left = None
            self.length = 0
        self._sock = None
    
    def isclosed(self):
        return self._sock is None
    
    @property
    def closed(self):
        return self.isclosed()
    
    def readinto(self, buf):
        if not isinstance(buf, memoryview):
            buf = memoryview(buf)
        if self.chunked:
            return self._read_chunked(buf)
        else:
            return self._read_raw(buf)
    
    def read(self, amt=None):
        if amt is not None:
            amt = int(amt)
            if amt < 0:
                amt = None
        if self.chunked:
            return self._read_chunked(amt)
        else:
            return self._read_raw(amt)
    
    def _read_chunked(self, arg):
        arg_is_memoryview = isinstance(arg, memoryview)
        if not arg_is_memoryview:
            chunks = []
        total = 0
        
        while not self.isclosed():
            
            if self.chunk_left is None:
                # Need to read a new chunk header
                line = self._sock.readline()
                if not line.endswith(b"\r\n"):
                    # Malformed data: invalid chunk header
                    self._close(True)
                    break
                
                # Strip chunk extensions
                x = line.find(b';')
                if x != -1:
                    line = line[:x]
                
                try:
                    self.chunk_left = int(line.strip(), 16)
                except ValueError:
                    # Malformed data: invalid chunk size
                    self._close(True)
                    break
                
                if self.chunk_left < 0:
                    # Malformed data: negative chunk size
                    self._close(True)
                    break
                
                if self.chunk_left == 0:
                    # Final chunk: consume trailers until blank line, then done
                    while True:
                        line = self._sock.readline()
                        if line == b"\r\n":
                            # End of Content
                            self.chunk_left = None
                            self.length = 0
                            break
                        if line == b"":
                            # Malformed data: missing CRLF after final chunk (premature EOF)
                            break
                    self.close()
                    break
            
            nread = 0
            if arg_is_memoryview:  # readinto()
                to_read = min(self.chunk_left, len(arg) - total)
                if to_read > 0:
                    nread = self._sock.readinto(arg[total:total+to_read])
                else:
                    break
            else:  # read()
                if arg is None:
                    to_read = self.chunk_left
                elif arg <= 0:
                    return b""
                else:
                    to_read = min(self.chunk_left, arg - total)
                if to_read > 0:
                    data = self._sock.read(to_read)
                    if data:
                        chunks.append(data)
                        nread = len(data)
                else:
                    break
            
            if nread <= 0:
                # EOF
                self.close()
                break
            
            total += nread
            self.chunk_left -= nread
            
            if self.chunk_left < 0:
                # Malformed data: over-read
                self._close(True)
                break
            
            elif self.chunk_left == 0:
                # We finished the chunk: validate trailing CRLF immediately.
                crlf = self._sock.read(2)
                if crlf != b"\r\n":
                    # Malformed data: missing CRLF after this chunk
                    self._close(True)
                    break
                self.chunk_left = None  # ready for next chunk header
        
        if arg_is_memoryview:
            return total
        if len(chunks) > 1:
            return b"".join(chunks)
        if len(chunks) == 1:
            return chunks[0]
        return b""  # EOF
    
    def _read_raw(self, arg):
        arg_is_memoryview = isinstance(arg, memoryview)
        
        if self.isclosed():
            # already EOF
            if arg_is_memoryview:
                res = 0
            else:
                res = b""
        elif self.length is None:
            if arg_is_memoryview:  # readinto()
                res = self._sock.readinto(arg)
                if res <= 0:
                    # EOF
                    self.close()
            elif arg == 0:
                return b""
            else:  # read()
                res = self._sock.read() if arg is None else self._sock.read(arg)
                if not res:
                    # EOF
                    self.close()
        elif self.length <= 0:
            if arg_is_memoryview:
                res = 0
            else:
                res = b""
            self.close()
        else:
            nread = 0
            if arg_is_memoryview:  # readinto()
                to_read = min(self.length, len(arg))
                if to_read > 0:
                    nread = res = self._sock.readinto(arg[:to_read])
                else:
                    res = 0
            else:  # read()
                if arg is None:
                    to_read = self.length
                elif arg <= 0:
                    return b""
                else:
                    to_read = min(self.length, arg)
                if to_read > 0:
                    res = self._sock.read(to_read)
                    if res:
                        nread = len(res)
                else:
                    res = b""
            
            if nread <= 0:
                self.close()
            else:
                self.length -= nread
                if self.length <= 0:
                    self.close()
        
        return res
    
    def getheader(self, name, default=None):
        if isinstance(name, str):
            name = name.encode(_ENCODE_HEAD)
        name = name.lower()
        if name in self.headers:
            value = self.headers[name]
            try:
                value = value.decode(_DECODE_HEAD)
            except UnicodeError:
                value = default
            return value
        else:
            return default
    
    def getheaders(self):  # incompat, returns {bytes:bytes, ...}
        return self.headers.items()
    
    def getcookie(self, name, default=None):  # extension
        if isinstance(name, str):
            name = name.encode(_ENCODE_HEAD)
        if name in self.cookies:
            value = self.cookies[name]
            x = value.find(b';')
            if x != -1:
                value = value[:x]
            value = value.decode(_DECODE_HEAD)
            return value
        else:
            return default
    
    def getcookies(self):  # extension, returns {bytes:bytes, ...}
        return self.cookies.items()
    
#    def iter_content(self, chunk_size=1024):  # extension
#        chunk_size = int(chunk_size)
#        if chunk_size <= 0:
#            raise ValueError("chunk_size must be > 0")
#        while True:
#            b = self.read(chunk_size)
#            if not b:
#                return
#            yield b
    
#    def iter_content_into(self, buf):  # extension
#        bmv = buf if isinstance(buf, memoryview) else memoryview(buf)
#        while True:
#            n = self.readinto(bmv)
#            if not n:
#                return
#            yield n

class HTTPConnection:
    default_port = HTTP_PORT
    auto_open = 1
    debuglevel = 0
    
    def __enter__(self):  # extension
        return self
    
    def __exit__(self, exc_type, exc_value, traceback):  # extension
        self.close()
        return False
    
    def __init__(self, host, port=None, timeout=None, source_address=None, blocksize=1024):
        self.host, self.port = parse_host_port(host, port)
        if not self.host:
            raise ValueError("invalid host")
        if self.port is None:
            self.port = self.default_port
        self.timeout = timeout
#        self.source_address = source_address  # not used
        self.blocksize = blocksize
        self.sock = None
        self._method = None
        self._url = None
        self.__response = None
    
    def set_debuglevel(self, level):
        self.debuglevel = level
    
    def connect(self):
        self.sock = create_connection((self.host, self.port), self.timeout)
    
    def close(self):
        if self.sock is not None:
            self.sock.close()
            self.sock = None
        self.__response = None
    
    def _sendall(self, data):
        if self.sock is None:
            raise NotConnected()
        try:
            self.sock.sendall(data)
        except OSError:
            raise NotConnected()
    
    def request(self, method, url, body=None, headers=None, cookies=None,
                *, encode_chunked=False):
        if isinstance(body, str):
            body = body.encode(_ENCODE_BODY)
        
        have_accept_encoding = False
        have_content_length = False
        have_host = False
        have_transfer_encoding = False
        
        if headers is not None:
            for name in headers:  # header names must be strings
                if isinstance(name, (bytes, bytearray)):
                    name = name.decode(_DECODE_HEAD)
                name = name.lower()
                if name == "accept-encoding":
                    have_accept_encoding = True
                elif name == "content-length":
                    have_content_length = True
                elif name == "host":
                    have_host = True
                elif name == "transfer-encoding":
                    have_transfer_encoding = True
        
        self.putrequest(method, url, skip_accept_encoding=have_accept_encoding, skip_host=have_host)
        
        # chunked encoding will happen if HTTP/1.1 is used and either
        # the caller passes encode_chunked=True or the following
        # conditions hold:
        # 1. content-length has not been explicitly set
        # 2. the body is a file or iterable, but not a str or bytes-like
        # 3. Transfer-Encoding has NOT been explicitly set by the caller
        
        if not have_content_length:
            # only chunk body if not explicitly set for backwards
            # compatibility, assuming the client code is already handling the
            # chunking
            if not have_transfer_encoding:
                # if content-length cannot be automatically determined, fall
                # back to chunked encoding
                encode_chunked = False
                
                if body is None:
                    # do an explicit check for not None here to distinguish
                    # between unset and set but empty
                    if method.upper() in _METHODS_EXPECTING_BODY:
                        content_length = 0
                    else:
                        content_length = None
                elif isinstance(body, (bytes, bytearray, memoryview)):
                    content_length = len(body)
                else:
                    content_length = None
                
                if content_length is None:
                    if body is not None:
                        encode_chunked = True
                        self.putheader(b"Transfer-Encoding", b"chunked")
                else:
                    self.putheader(b"Content-Length", str(content_length))
        else:
            encode_chunked = False
        
        self.putheaders(headers, cookies)
        
        self.endheaders(body, encode_chunked=encode_chunked)
    
    def putrequest(self, method, url, skip_host=False, skip_accept_encoding=False):
        if self.__response is not None:
            if not self.__response.isclosed():
                raise CannotSendRequest()
            self.__response = None
        
        self._method = method
        self._url = url or "/"
        
        request = b"%s %s HTTP/1.1\r\n" % (encode_and_validate(self._method, _ENCODE_HEAD), encode_and_validate(self._url, _ENCODE_HEAD))
        
        try:
            self._sendall(request)
        except NotConnected:
            self.close()
            if self.auto_open:
                self.connect()
                self._sendall(request)
            else:
                raise
        
        # Issue some standard headers for better HTTP/1.1 compliance
        if not skip_host:
            host = self.host
            if ':' in host and not host.startswith('['):
                host = "[%s]" % (host,)
            if self.port == self.default_port:
                self.putheader(b"Host", host)
            else:
                self.putheader(b"Host", "%s:%d" % (host, self.port))
        if not skip_accept_encoding:
            self.putheader(b"Accept-Encoding", b"identity")
    
    def putheaders(self, headers, cookies=None):  # extension
        if headers is not None:
            for key, val in headers.items():
                self.putheader(key, val)
        
        if cookies is not None:
            values = []
            for key, val in cookies.items():
                values.append(b"%s=%s" % (key.encode(_ENCODE_HEAD), encode_and_validate(val, _ENCODE_HEAD)))
            if len(values) == 1:
                self.putheader(b"Cookie", values[0])
            elif len(values):
                self.putheader(b"Cookie", b"; ".join(values))
    
    def putheader(self, header, *values):
        if self.__response is not None:
            raise CannotSendHeader()
        
        if len(values) == 1:
            values = encode_and_validate(values[0], _ENCODE_HEAD)
        elif len(values):
            # no idea why CPython joins with "\r\n\t" rather than ", "
            values = b"\r\n\t".join([encode_and_validate(v, _ENCODE_HEAD) for v in values])
        else:
            return
        if isinstance(header, str):
            header = header.encode(_ENCODE_HEAD)
        self._sendall(b"%s: %s\r\n" % (header, values))
    
    def endheaders(self, message_body=None, *, encode_chunked=False):
        if self.__response is not None:
            raise CannotSendHeader()
        self._sendall(b"\r\n")
        if message_body is not None:
            self.send(message_body, encode_chunked=encode_chunked)
    
    def send(self, data, *, encode_chunked=False):  # encode_chunked is an extension
        if isinstance(data, str):
            data = data.encode(_ENCODE_BODY)
        if self.debuglevel > 0:
            print("send:", type(data).__name__)
        
        if data is None:
            pass
        elif isinstance(data, (bytes, bytearray, memoryview)):
            if data:
                if self.debuglevel > 0:
                    print("send:", type(data).__name__, len(data))
                if encode_chunked:
                    self._sendall(b"%X\r\n" % (len(data),))
                self._sendall(data)
                if encode_chunked:
                    self._sendall(b"\r\n")
        elif hasattr(data, "read"):
            while True:
                d = data.read(self.blocksize)  # no short reads on micropython
                if isinstance(d, str):
                    d = d.encode(_ENCODE_BODY)
                if self.debuglevel > 0:
                    print("send:", type(d).__name__, len(d))
                if not d:
                    break
                if encode_chunked:
                    self._sendall(b"%X\r\n" % (len(d),))
                self._sendall(d)
                if encode_chunked:
                    self._sendall(b"\r\n")
        elif isiterator(data):  # includes generators (bytes-like was handled earlier)
            for d in data:
                if isinstance(d, str):
                    d = d.encode(_ENCODE_BODY)
                if d is None:
                    if self.debuglevel > 0:
                        print("send: None")
                    continue
                elif isinstance(d, (bytes, bytearray, memoryview)):
                    if self.debuglevel > 0:
                        print("send:", type(d).__name__, len(d))
                    if not d:
                        continue
                else:
                    raise TypeError("unexpected data")
                if encode_chunked:
                    self._sendall(b"%X\r\n" % (len(d),))
                self._sendall(d)
                if encode_chunked:
                    self._sendall(b"\r\n")
        else:
            raise TypeError("unexpected data")
        
        if encode_chunked:
            if self.debuglevel > 0:
                print("send: terminating chunk")
            self._sendall(b"0\r\n\r\n")
    
    def getresponse(self, extra_headers=False, parse_cookies=False):  # extra_headers and parse_cookies are an extension
        if self.__response is not None:
            raise ResponseNotReady()
        try:
            self.__response = HTTPResponse(self.sock, self.debuglevel, self._method, self._url, extra_headers=extra_headers, parse_cookies=parse_cookies)
            return self.__response
        except Exception:
            self.close()
            raise

try:
    import ssl
except ImportError:
    pass
else:
    class HTTPSConnection(HTTPConnection):
        default_port = HTTPS_PORT
        
        def __init__(self, *args, context=None, **kwargs):
            super().__init__(*args, **kwargs)
            if context is None:
                if hasattr(ssl, "SSLContext"):
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    context.verify_mode = ssl.CERT_NONE
                else:
                    context = None
            self._context = context
        
        def connect(self):
            super().connect()
            if self._context is None:
                try:
                    self.sock = ssl.wrap_socket(self.sock, server_hostname=self.host)
                except TypeError:
                    self.sock = ssl.wrap_socket(self.sock)
            else:
                self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host)

class HTTPException(Exception): pass
class NotConnected(HTTPException): pass
class ImproperConnectionState(HTTPException): pass
class CannotSendRequest(ImproperConnectionState): pass
class CannotSendHeader(ImproperConnectionState): pass
class ResponseNotReady(ImproperConnectionState): pass
class BadStatusLine(HTTPException): pass
class RemoteDisconnected(BadStatusLine): pass

