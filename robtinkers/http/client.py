import socket

HTTP_PORT = const(80)
HTTPS_PORT = const(443)

DECODE_HEAD = const(None)
DECODE_BODY = const(None)
ENCODE_HEAD = const(None)
ENCODE_BODY = const(None)

OK = const(200)

_CS_IDLE = const(1) # 'Idle'
_CS_REQ_STARTED = const(2) # 'Request-started'
_CS_REQ_SENT = const(3) # 'Request-sent'

# We always set the Content-Length header for these methods because some
# servers will otherwise respond with a 411
_METHODS_EXPECTING_BODY = {'PATCH', 'POST', 'PUT'}

def _create_connection(address, timeout=None):
    host, port = address
    err = None
    for res in socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM):
        af, socktype, proto, canonname, sa = res
        sock = None
        try:
            sock = socket.socket(af, socktype, proto)
            if timeout is not None:
                sock.settimeout(timeout)
            sock.connect(sa)
            return sock
        except OSError as e:
            err = e
            if sock is not None:
                sock.close()
    if err is None:
        raise OSError("getaddrinfo failed")
    else:
        raise err

def _parse_status(line):
    if not line:
        raise RemoteDisconnected()
    
    try:
        line = line.decode(DECODE_HEAD).strip()
        version, status, reason = line.split(None, 2)
    except UnicodeError:
        # empty version will cause next test to fail.
        version = ""
    except ValueError:
        try:
            version, status = line.split(None, 1)
            reason = ""
        except ValueError:
            # empty version will cause next test to fail.
            version = ""
    
    if not version.startswith("HTTP/"):
        raise BadStatusLine()
    
    # The status code is a three-digit number
    try:
        status = int(status, 10)
        if status < 100 or status > 999:
            raise BadStatusLine()
    except ValueError:
        raise BadStatusLine()
    return version, status, reason

def _parse_headers_and_cookies(fp, header_filter, cookie_filter):
    headers = {}
    cookies = {}
    last_header = None
    
    while True:
        line = fp.readline()
        if not line.rstrip(b'\r\n'):
            return headers, cookies
        
        try:
            line = line.decode(DECODE_HEAD)
        except UnicodeError:
            last_header = None
            continue
        
        if line.startswith((' ', '\t')):
            if last_header is not None:
                headers[last_header] += ' ' + line.strip()
            continue
        if ':' not in line:
            last_header = None
            continue
        
        key, val = line.split(':', 1)
        key = key.strip().lower()
        val = val.strip()
        
        if key == 'set-cookie':
            key, x, v = val.partition('=')
            if x and cookie_filter(key, v):
                if v.startswith('"'):
                    x = v.find('"', 1)
                    cookies[key] = v[1:x] if x > 0 else v[1:]
                else:
                    cookies[key] = v.split(';', 1)[0]
            last_header = None  # multi-line set-cookie headers not supported
        else:
            if header_filter(key, val):
                if key in headers:
                    headers[key] += ', ' + val
                    last_header = key
                else:
                    headers[key] = val
                    last_header = key
            else:
                last_header = None

class HTTPResponse:
    def __init__(self, sock, debuglevel=0, method=None, url=None):
        self.fp = sock
        self.debuglevel = debuglevel
        self._method = method
        self.url = url
        
        self.headers = None
        self.cookies = None
        
        self.version = None
        self.status = None
        self.reason = None
        
        self.chunked = None
        self.chunk_left = None
        self.length = None
        self.will_close = None
    
    @staticmethod
    def header_filter(key, val): # extension
        return True
    
    @staticmethod
    def cookie_filter(key, val): # extension
        return True
    
    def begin(self):
        if self.headers is not None:
            # we've already started reading the response
            return
        
        # read until we get a non-100 response
        while True:
            try:
                status_line = self.fp.readline()
                if self.debuglevel > 0:
                    print("reply:", repr(status_line))
                version, status, reason = _parse_status(status_line)
            except Exception as e:
                self.close()
                raise e
            if status != 100:
                break
            # skip the header from the 100 response
            while True:
                line = self.fp.readline()
                if self.debuglevel > 0:
                    print("skipping:", repr(line))
                if not line.rstrip(b'\r\n'):
                    break
        
        self.status = status
        self.reason = reason.strip()
        if version in ("HTTP/1.0", "HTTP/0.9"):
            # Some servers might still return "0.9", treat it as 1.0 anyway
            self.version = 10
        elif version.startswith("HTTP/1."):
            self.version = 11   # use HTTP/1.1 code for HTTP/1.x where x>=1
        else:
            raise UnknownProtocol()
        
        self.headers, self.cookies = _parse_headers_and_cookies(self.fp, self.header_filter, self.cookie_filter)
        if self.debuglevel > 0:
            for hdr, val in self.headers.items():
                print("header:", hdr + ":", val)
            for hdr, val in self.cookies.items():
                print("cookie:", hdr + ":", val)
        
        # are we using the chunked-style of transfer encoding?
        if "chunked" in self.headers.get("transfer-encoding", "").lower():
            self.chunked = True
            self.chunk_left = None
        else:
            self.chunked = False
        
        # will the connection close at the end of the response?
        if self.version == 11:
            self.will_close = 'close' in self.headers.get('connection', '').lower()
        else:
            self.will_close = bool(self.headers.get('keep-alive', ''))
        
        # do we have a Content-Length?
        # NOTE: RFC 2616, S4.4, #3 says we ignore this if "chunked"
        self.length = None
        length = self.headers.get("content-length")
        if length and not self.chunked:
            try:
                self.length = int(length, 10)
            except ValueError:
                self.length = None
            else:
                if self.length < 0:  # ignore nonsensical negative lengths
                    self.length = None
        else:
            self.length = None
        
        # does the body have a fixed length? (of zero)
        if (status == 204 or status == 304 or
            100 <= status < 200 or      # 1xx codes
            self._method == "HEAD"):
            self.length = 0
        
        # if the connection remains open, and we aren't using chunked, and
        # a content-length was not provided, then assume that the connection
        # WILL close.
        if (not self.will_close and
            not self.chunked and
            self.length is None):
            self.will_close = True
    
    def close(self):
        if self.fp is not None:
            self.fp.close()
            self.fp = None
    
    def isclosed(self):
        return self.fp is None
    
    def read(self, amt=None):
        if amt is not None and amt < 0:
            amt = None
        
        if self.chunked:
            return self._read_chunked(amt)
        elif self.isclosed():
            return b''
        elif self.length is not None and self.length < 0:
            self.close()
            return b''
        elif amt is None:
            if self.length is None:
                data = self.fp.read()
                self.length = 0
                self.close()        # we read everything
            else:
                data = self.fp.read(self.length) # no short reads on micropython
                self.length -= len(data)
            return data
        else:
            if self.length is None:
                data = self.fp.read(amt) # no short reads on micropython
            elif self.length == 0 and amt > 0:
                self.close()        # nothing left
                data = b''
            else:
                if self.length is None:
                    n = amt
                else:
                    n = min(self.length, amt)
                data = self.fp.read(n) # no short reads on micropython
                self.length -= len(data)
            return data
    
    def readinto(self, b):
        if self.fp is None:
            return 0
        
        if self.chunked:
            # Chunked readinto is complex; fallback to read() and copy for simplicity
            data = self._read_chunked(len(b))
            if not data:
                return 0
            n = len(data)
            b[:n] = data
            return n
        
        if self.length is not None:
            if len(b) > self.length:
                # clip the read to the "end of response"
                b = memoryview(b)[0:self.length]
        
        n = self.fp.readinto(b) # no short reads on micropython
        if self.length is not None:
            self.length -= n
        if n != len(b):
            self.close()
        return n
    
    def _read_chunked(self, amt):
        if amt is not None and amt < 0:
            amt = None
        chunks = []
        
        while True:
            
            if self.chunk_left is not None:
                # Read chunk data
                if amt is None:
                    n = self.chunk_left
                else:
                    n = min(self.chunk_left, amt)
                data = self.fp.read(n) # no short reads on micropython
                chunks.append(data)
                # Check for incomplete read
                if len(data) != n:
                    self.close()
                    break
                # Update counters
                self.chunk_left -= len(data)
                if amt is not None:
                    amt -= len(data)
                # Finished current chunk? Consume the trailing CRLF
                if self.chunk_left == 0:
                    crlf = self.fp.read(2) # no short reads on micropython
                    if crlf != b'\r\n':
                        self.close()
                        break
                    self.chunk_left = None
            else:
                # Read chunk header
                line = self.fp.readline()
                if not line.endswith(b'\r\n'):
                    self.close()
                    break
                i = line.find(b';')
                if i >= 0:
                    line = line[:i] # strip chunk-extensions
                try:
                    self.chunk_left = int(line.strip(), 16)
                except ValueError:
                    self.close()
                    break
                if self.chunk_left < 0:
                    self.close()
                    break
                # End of stream? Consume until blank line
                if self.chunk_left == 0:
                    while True:
                        line = self.fp.readline()
                        if line == b'\r\n' or line == b'':
                            break
                    self.chunk_left = None
                    break
            
            if amt == 0:
                break
        
        if self.isclosed():
            self.chunk_left = None
        return b''.join(chunks)
    
    def getcookie(self, name, default=None):
        if self.cookies is None:
            raise ResponseNotReady()
        return self.cookies.get(name, default)
    
    def getheader(self, name, default=None):
        if self.headers is None:
            raise ResponseNotReady()
        return self.headers.get(name.lower(), default)
    
    def getheaders(self):
        if self.headers is None:
            raise ResponseNotReady()
        return list(self.headers.items())

class HTTPConnection:
    response_class = HTTPResponse
    default_port = HTTP_PORT
    auto_open = 1
    debuglevel = 0
    
    def __init__(self, host, port=None, timeout=None, *, blocksize=1024):
        self.timeout = timeout
        self.blocksize = blocksize
        self.sock = None
        self._buffer = []
        self.__response = None
        self.__state = _CS_IDLE
        self._method = None
        
        if port is None:
            self.host = host
            self.port = self.default_port
        else:
            self.host = host
            self.port = port
    
    def set_debuglevel(self, level):
        self.debuglevel = level
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
    
    def connect(self):
        self.sock = _create_connection((self.host, self.port), self.timeout)
        # Might fail in OSs that don't implement TCP_NODELAY
        try:
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass
    
    def close(self):
        self.__state = _CS_IDLE
        try:
            sock = self.sock
            if sock:
                self.sock = None
                sock.close()   # close it manually... there may be other refs
        finally:
            response = self.__response
            if response:
                self.__response = None
                response.close()
    
    def send(self, data, *, encode_chunked=False): # encode_chunked is an extension
        if self.sock is None:
            if self.auto_open:
                self.connect()
            else:
                raise NotConnected()
        
        if isinstance(data, str):
            data = data.encode(ENCODE_BODY)
        if self.debuglevel > 0:
            print("send:", repr(data))
        
        if data is None:
            pass
        elif isinstance(data, (bytes, bytearray, memoryview)):
            if data:
                if encode_chunked:
                    self.sock.sendall(f"{len(data):X}\r\n".encode(None)) # ascii
                self.sock.sendall(data)
                if encode_chunked:
                    self.sock.sendall(b'\r\n')
        elif hasattr(data, 'read'):
            if self.debuglevel > 0:
                print("sending a readable")
            while True:
                d = data.read(self.blocksize) # no short reads on micropython
                if isinstance(d, str):
                    if self.debuglevel > 0:
                        print("encoding file")
                    d = d.encode(ENCODE_BODY)
                if not d:
                    break
                if encode_chunked:
                    self.sock.sendall(f"{len(d):X}\r\n".encode(None)) # ascii
                self.sock.sendall(d)
                if encode_chunked:
                    self.sock.sendall(b'\r\n')
        elif hasattr(data, '__next__'):
            for d in data:
                if isinstance(d, str):
                    d = d.encode(ENCODE_BODY)
                if d is None:
                    if self.debuglevel > 0:
                        print('Zero length chunk ignored')
                    continue
                elif isinstance(d, (bytes, bytearray, memoryview)):
                    if not d:
                        continue
                else:
                    raise TypeError(f"unexpected data {type(d)}")
                if encode_chunked:
                    self.sock.sendall(f"{len(d):X}\r\n".encode(None)) # ascii
                self.sock.sendall(d)
                if encode_chunked:
                    self.sock.sendall(b'\r\n')
        else:
            raise TypeError(f"unexpected data {type(data)}")
    
    def send_terminating_chunk(self, headers=None):
        if headers is None:
            self.sock.sendall(b'0\r\n\r\n')
            return
        
        self.sock.sendall(b'0\r\n')
        for h in headers:
            hdr = '%s: %s\r\n' % (str(h[0], ENCODE_BODY), '\r\n\t'.join([str(v, ENCODE_BODY) for v in h[1:]]))
            self.sock.sendall(hdr.encode(ENCODE_BODY))
        self.sock.sendall(b'\r\n')
    
    def putrequest(self, method, url, skip_host=False, skip_accept_encoding=False):
        if self.__state == _CS_IDLE:
            self.__state = _CS_REQ_STARTED
        else:
            raise CannotSendRequest()
        
        self._method = method
        url = url or '/'
        
        request = '%s %s %s' % (method, url, 'HTTP/1.1')
        if any(c in request for c in '\0\r\n'):
            raise ValueError("method/url can't contain control characters")
        self._buffer.append(request.encode(ENCODE_HEAD))
        
        # Issue some standard headers for better HTTP/1.1 compliance
        if not skip_host:
            self.putheader('Host', '%s:%s' % (self.host, self.port))
        if not skip_accept_encoding:
            self.putheader('Accept-Encoding', 'identity')
    
    def putheader(self, header, *values):
        if self.__state != _CS_REQ_STARTED:
            raise CannotSendHeader()
        
        hdr = '%s: %s' % (str(header, ENCODE_HEAD), '\r\n\t'.join([str(v, ENCODE_HEAD) for v in values]))
        self._buffer.append(hdr.encode(ENCODE_HEAD))
    
    def endheaders(self, message_body=None, *, encode_chunked=False):
        if self.__state == _CS_REQ_STARTED:
            self.__state = _CS_REQ_SENT
        else:
            raise CannotSendHeader()
        
        self._buffer.extend((b'', b''))
        msg = b'\r\n'.join(self._buffer)
        del self._buffer[:]
        self.send(msg)
        
        if message_body is not None:
            self.send(message_body, encode_chunked=encode_chunked)
            if encode_chunked:
                # Send the terminating chunk
                self.send_terminating_chunk()
    
    def request(self, method, url, body=None, headers=None, *,
                encode_chunked=False):
        if headers is None:
            headers = {}
        
        if isinstance(body, str):
            body = body.encode(ENCODE_BODY)
        
        # Honor explicitly requested Host: and Accept-Encoding: headers.
        header_names = frozenset(k.lower() for k in headers)
        skips = {}
        if 'host' in header_names:
            skips['skip_host'] = 1
        if 'accept-encoding' in header_names:
            skips['skip_accept_encoding'] = 1
        
        self.putrequest(method, url, **skips)
        
        # chunked encoding will happen if HTTP/1.1 is used and either
        # the caller passes encode_chunked=True or the following
        # conditions hold:
        # 1. content-length has not been explicitly set
        # 2. the body is a file or iterable, but not a str or bytes-like
        # 3. Transfer-Encoding has NOT been explicitly set by the caller
        
        if 'content-length' not in header_names:
            # only chunk body if not explicitly set for backwards
            # compatibility, assuming the client code is already handling the
            # chunking
            if 'transfer-encoding' not in header_names:
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
                        if self.debuglevel > 0:
                            print('Unable to determine size of %r' % body)
                        encode_chunked = True
                        self.putheader('Transfer-Encoding', 'chunked')
                else:
                    self.putheader('Content-Length', str(content_length))
        else:
            encode_chunked = False
        
        for hdr, value in headers.items():
            self.putheader(hdr, value)
        self.endheaders(body, encode_chunked=encode_chunked)
    
    def getresponse(self):
        if self.__response and self.__response.isclosed():
            self.__response = None
        
        if self.__state != _CS_REQ_SENT or self.__response:
            raise ResponseNotReady(self.__state)
        
        response = self.response_class(self.sock, self.debuglevel, self._method)
        
        try:
            try:
                response.begin()
            except ConnectionError:
                self.close()
                raise
            if response.will_close is None:
                raise ImproperConnectionState()
            self.__state = _CS_IDLE
            
            if response.will_close:
                # this effectively passes the connection to the response
                self.close()
            else:
                # remember this, so we can tell when it is complete
                self.__response = response
            
            return response
        except:
            response.close()
            raise

try:
    import ssl
except ImportError:
    pass
else:
    class HTTPSConnection(HTTPConnection):
        default_port = HTTPS_PORT
        
        def __init__(self, host, port=None, timeout=None, *, blocksize=1024, context=None):
            super().__init__(host, port, timeout, blocksize=blocksize)
            if context is None:
                if hasattr(ssl, 'SSLContext'):
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    context.verify_mode = ssl.CERT_NONE
                else:
                    context = None
            self._context = context
        
        def connect(self):
            sock = _create_connection((self.host, self.port), self.timeout)
            if self._context:
                self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
            else:
                self.sock = ssl.wrap_socket(sock)

class HTTPException(Exception): pass
class NotConnected(HTTPException): pass
#class InvalidURL(HTTPException): pass
class UnknownProtocol(HTTPException): pass
#class UnknownTransferEncoding(HTTPException): pass
#class UnimplementedFileMode(HTTPException): pass
class IncompleteRead(HTTPException): pass
class ImproperConnectionState(HTTPException): pass
class CannotSendRequest(ImproperConnectionState): pass
class CannotSendHeader(ImproperConnectionState): pass
class ResponseNotReady(ImproperConnectionState): pass
class BadStatusLine(HTTPException): pass
#class LineTooLong(HTTPException): pass
class RemoteDisconnected(BadStatusLine): pass

