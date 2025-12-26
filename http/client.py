# http/client.py

from micropython import const
import socket

HTTP_PORT = const(80)
HTTPS_PORT = const(443)

OK = const(200)

# We always set the Content-Length header for these methods because some
# servers will otherwise respond with a 411
_METHODS_EXPECTING_BODY = frozenset({'PATCH', 'POST', 'PUT'})

_IMPORTANT_HEADERS = frozenset({
    b'connection', # required
    b'content-encoding',
    b'content-length', # required
    b'content-type',
    b'etag',
    b'keep-alive', # required
    b'location', # required
    b'retry-after',
    b'transfer-encoding', # required
    b'www-authenticate',
})

_DECODE_HEAD = const('iso-8859-1')
_DECODE_BODY = const('utf-8')
_ENCODE_HEAD = const('iso-8859-1')
_ENCODE_BODY = const('utf-8')

def _enck(b, *args): # encode-and-check helper
    if isinstance(b, (bytes, bytearray)):
        pass
    elif hasattr(b, 'encode'):
        b = b.encode(*args)
#    elif isinstance(b, memoryview):
#        b = bytes(b)
    else:
        raise TypeError('value must be bytes-like')
    if b'\0' in b or b'\r' in b or b'\n' in b:
        raise ValueError('value can\'t contain control characters')
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
                if timeout != 0: # 0 would be a non-blocking socket
                    sock.settimeout(timeout)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except (AttributeError, OSError):
                pass
            sock.connect(a)
            return sock
        except OSError:
            if sock is not None:
                sock.close()
    raise OSError('create_connection() failed')

def parse_headers(sock, *, extra_headers=False, parse_cookies=None): # returns dict/s {str:bytes, ...}
    headers = {}
    if parse_cookies is not None:
        cookies = {}
    last_header = None
    
    while True:
        line = sock.readline()
        if not line or line == b'\r\n':
            if parse_cookies is not None:
                return headers, cookies
            else:
                return headers
        
        try:
            if line.startswith((b' ', b'\t')):
                if last_header is not None:
                    headers[last_header] += b' ' + line.strip()
                continue
            
            x = line.find(b':')
            if x == -1:
                continue
            key = line[:x].strip().lower()
            val = line[x+1:].strip()
            
            if key == b'set-cookie':
                if parse_cookies == True:
                    key, sep, val = val.partition(b'=')
                    if sep:
                        key = key.decode(_DECODE_HEAD)
                        cookies[key] = val # includes any quotes and parameters
            elif extra_headers == True or key in _IMPORTANT_HEADERS \
                    or (isinstance(extra_headers, (frozenset, set, list, tuple)) and key in extra_headers):
                key = key.decode(_DECODE_HEAD)
                if key in headers:
                    headers[key] += b', ' + val
                else:
                    headers[key] = val
                last_header = key
                continue
        except UnicodeError:
            pass
        
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
        
        self.version, self.status, self.reason = self._read_status()
        if self.debuglevel > 0:
            print('status:', repr(self.version), repr(self.status), repr(self.reason))
        
        self.headers, self.cookies = parse_headers(self._sock, extra_headers=extra_headers, parse_cookies=parse_cookies or False)
        if self.debuglevel > 0:
            for key, val in self.headers.items():
                print('header:', repr(key), '=', repr(val))
            for key, val in self.cookies.items():
                print('cookie:', repr(key), '=', repr(val))
        
        # are we using the chunked-style of transfer encoding?
        self.chunked = b'chunked' in self.headers.get('transfer-encoding', b'').lower()
        self.chunk_left = None
        
        # will the connection close at the end of the response?
        if self.status == 101:
            self.will_close = True
        elif self.version == 11:
            self.will_close = b'close' in self.headers.get('connection', b'').lower()
        else:
            self.will_close = not (b'keep-alive' in self.headers.get('connection', b'').lower() or self.headers.get('keep-alive'))
        
        # do we have a Content-Length?
        # NOTE: RFC 2616, S4.4, #3 says we ignore this if chunked
        self.length = None
        length = self.getheader('content-length')
        if length and not self.chunked:
            try:
                self.length = int(length, 10)
            except ValueError:
                pass # self.length is already None
            else:
                if self.length < 0:  # ignore nonsensical negative lengths
                    self.length = None
        
        # does the body have a fixed length? (of zero)
        if (self.status == 204 or self.status == 304 or
            100 <= self.status < 200 or      # 1xx codes
            self._method == 'HEAD'):
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
                print('status:', repr(line))
            
            if not line.startswith(b'HTTP/'):
                raise BadStatusLine()
            
            try:
                line = line.decode(_DECODE_HEAD).strip()
                line = line.split(None, 2)
                if len(line) == 3:
                    version, status, reason = line
                elif len(line) == 2:
                    version, status = line
                    reason = ''
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
                if not line or line == b'\r\n':
                    break
                if self.debuglevel > 0:
                    print('header:', repr(line))
        
        if version in ('HTTP/1.0', 'HTTP/0.9'):
            # Some servers might still return 0.9, treat it as 1.0 anyway
            version = 10
        elif version.startswith('HTTP/1.'):
            version = 11 # use HTTP/1.1 code for HTTP/1.x where x>=1
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
        if not isinstance(arg, memoryview):
            chunks = []
        total = 0
        
        while True:
            if self.chunk_left is None:
                # Need to read a new chunk header
                line = self._sock.readline()
                if not line.endswith(b'\r\n'):
                    self._close(True)  # Malformed data: invalid chunk header
                    break
                
                # Strip chunk extensions
                i = line.find(b';')
                if i >= 0:
                    line = line[:i]
                
                try:
                    self.chunk_left = int(line.strip(), 16)
                except ValueError:
                    self._close(True)  # Malformed data: invalid chunk size
                    break
                
                if self.chunk_left < 0:
                    self._close(True)  # Malformed data: negative chunk size
                    break
                
                # Final chunk: consume trailers until blank line, then done
                if self.chunk_left == 0:
                    while True:
                        line = self._sock.readline()
                        if line == b'\r\n' or line == b'':
                            break
                    self.chunk_left = None
                    self.length = 0
                    self.close()
                    break
            
            to_read = self.chunk_left
            
            if isinstance(arg, memoryview):  # readinto()
                to_read = min(to_read, len(arg) - total)
                if to_read <= 0:
                    break
                nread = self._sock.readinto(arg[total:total+to_read])
            else:  # read()
                if arg is not None:
                    to_read = min(to_read, arg - total)
                if to_read <= 0:
                    break
                data = self._sock.read(to_read)
                if data:
                    chunks.append(data)
                    nread = len(data)
                else:
                    nread = 0
            
            total += nread
            self.chunk_left -= nread
            
            if nread == 0 or self.chunk_left < 0:
                self.close()  # Malformed data
                break
            
            # if we finished the chunk, validate trailing CRLF immediately.
            if self.chunk_left == 0:
                crlf = self._sock.read(2)
                if crlf != b'\r\n':
                    # close connection, but still return the data already read
                    self._close(True)
                    break
                self.chunk_left = None  # ready for next chunk header
            
            # short read under specific circumstances to avoid the join() below
            if not isinstance(arg, memoryview) and arg is not None and total > 0:
                break
        
        if isinstance(arg, memoryview):
            return total
        if len(chunks) > 1:
            return b''.join(chunks)
        if len(chunks) == 1:
            return chunks[0]
        return b'' # EOF
    
    def _read_raw(self, arg):
        if isinstance(arg, memoryview):  # For `readinto()`
            if self.isclosed():
                res = 0
            elif self.length is None:
                res = self._sock.readinto(arg)
                if not res:
                    self.close()  # Finished reading
            elif self.length >= 0:
                to_read = min(len(arg), self.length)
                res = self._sock.readinto(arg[:to_read])
                if not res and to_read:
                    self.close()  # Close the connection, unexpected EOF
                self.length -= res
                if self.length <= 0:
                    self.close()  # Close the connection, over-read possible
            else:
                self.close()  # Malformed data
                res = 0
        else:  # For `read()` and `read(N)`
            if self.isclosed():
                res = b'' # EOF
            elif self.length is None:
                res = self._sock.read() if arg is None else self._sock.read(arg)
                if not res:
                    self.close()  # Finished reading
            elif self.length >= 0:
                to_read = min(self.length, arg if arg is not None else self.length)
                res = self._sock.read(to_read)
                if not res and to_read:
                    self.close()  # Close the connection, unexpected EOF
                self.length -= len(res)
                if self.length <= 0:
                    self.close()  # Close the connection, over-read possible
            else:
                self.close()  # Malformed data
                res = b'' # EOF
        return res
    
    def getheader(self, name, default=None):
        name = name.lower()
        if name in self.headers:
            value = self.headers[name]
            return value.decode(_DECODE_HEAD)
        else:
            return default
    
    def getheaders(self): # incompat, returns {str:bytes, ...}
        return self.headers.items()
    
    def getcookie(self, name, default=None): # extension
        if name in self.cookies:
            value = self.cookies[name]
            value = value.split(b';', 1)[0]
            return value.decode(_DECODE_HEAD)
        else:
            return default
    
    def getcookies(self): # extension, returns {str:bytes, ...}
        return self.cookies.items()
    
    def iter_content(self, chunk_size=1024): # extension
        chunk_size = int(chunk_size)
        if chunk_size <= 0:
            raise ValueError('chunk_size must be > 0')
        while True:
            b = self.read(chunk_size)
            if not b:
                return
            yield b
    
    def iter_content_into(self, buf): # extension
        bmv = buf if isinstance(buf, memoryview) else memoryview(buf)
        while True:
            n = self.readinto(bmv)
            if not n:
                return
            yield n

class HTTPConnection:
    default_port = HTTP_PORT
    auto_open = 1
    debuglevel = 0
    
    def __enter__(self): # extension
        return self
    
    def __exit__(self, exc_type, exc_value, traceback): # extension
        self.close()
        return False
    
    def __init__(self, host, port=None, timeout=None, blocksize=1024):
        self.host = host
        self.port = self.default_port if port is None else port
        self.timeout = timeout
        self.blocksize = blocksize
        
        self._sock = None
        self._method = None
        self._url = None
        
        self._response = None
    
    def set_debuglevel(self, level):
        self.debuglevel = level
    
    def connect(self):
        self._sock = create_connection((self.host, self.port), self.timeout)
    
    def close(self):
        if self._sock is not None:
            self._sock.close()
            self._sock = None
        self._response = None
    
    def _sendall(self, data):
        if self._sock is None:
            raise NotConnected()
        try:
            self._sock.sendall(data)
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
            for name in headers: # header names must be strings
                name = name.lower()
                if name == 'accept-encoding':
                    have_accept_encoding = True
                elif name == 'content-length':
                    have_content_length = True
                elif name == 'host':
                    have_host = True
                elif name == 'transfer-encoding':
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
                        self.putheader('Transfer-Encoding', 'chunked')
                else:
                    self.putheader('Content-Length', str(content_length))
        else:
            encode_chunked = False
        
        self.putheaders(headers, cookies)
        
        self.endheaders(body, encode_chunked=encode_chunked)
    
    def putrequest(self, method, url, skip_host=False, skip_accept_encoding=False):
        if self._response is not None:
            if self._response.isclosed():
                self._response = None
            else:
                self.close()
        
        self._method = method
        self._url = url or '/'
        
        request = b' '.join((self._method.encode(_ENCODE_HEAD), self._url.encode(_ENCODE_HEAD), b'HTTP/1.1\r\n'))
        if b'\0' in request or 0 <= request.find(b'\r') < len(request) - 2 or 0 <= request.find(b'\n') < len(request) - 2:
            raise ValueError('request can\'t contain control characters')
        
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
                host = '[%s]' % (host,)
            if self.port == self.default_port:
                self.putheader('Host', host)
            else:
                self.putheader('Host', '%s:%s' % (host, self.port))
        if not skip_accept_encoding:
            self.putheader('Accept-Encoding', 'identity')
    
    def putheaders(self, headers, cookies=None): # extension
        if headers is not None:
            for key, val in headers.items():
                self.putheader(key, val)
        
        if cookies is not None:
            values = []
            for key, val in cookies.items():
                values.append(b'%s=%s' % (key.encode(_ENCODE_HEAD), _enck(val)))
            if values:
                self.putheader('Cookie', b'; '.join(values))
    
    def putheader(self, header, *values):
        if len(values) == 0:
            return
        elif len(values) == 1:
            values = _enck(values[0], _ENCODE_HEAD)
        else:
            values = b'\r\n\t'.join([_enck(v, _ENCODE_HEAD) for v in values])
        self._sendall(b'%s: %s\r\n' % (header.encode(_ENCODE_HEAD), values))
    
    def endheaders(self, message_body=None, *, encode_chunked=False):
        self._sendall(b'\r\n')
        if message_body is not None:
            self.send(message_body, encode_chunked=encode_chunked)
    
    def send(self, data, *, encode_chunked=False): # encode_chunked is an extension
        if isinstance(data, str):
            data = data.encode(_ENCODE_BODY)
        if self.debuglevel > 0:
            print('send:', type(data).__name__)
        
        if data is None:
            pass
        elif isinstance(data, (bytes, bytearray, memoryview)):
            if data:
                if self.debuglevel > 0:
                    print('send:', type(data).__name__, len(data))
                if encode_chunked:
                    self._sendall(b'%X\r\n' % (len(data),))
                self._sendall(data)
                if encode_chunked:
                    self._sendall(b'\r\n')
        elif hasattr(data, 'read'):
            while True:
                d = data.read(self.blocksize) # no short reads on micropython
                if isinstance(d, str):
                    d = d.encode(_ENCODE_BODY)
                if self.debuglevel > 0:
                    print('send:', type(d).__name__, len(d))
                if not d:
                    break
                if encode_chunked:
                    self._sendall(b'%X\r\n' % (len(d),))
                self._sendall(d)
                if encode_chunked:
                    self._sendall(b'\r\n')
        elif isiterator(data):  # includes generators (bytes-like was handled earlier)
            for d in data:
                if isinstance(d, str):
                    d = d.encode(_ENCODE_BODY)
                if d is None:
                    if self.debuglevel > 0:
                        print('send: None')
                    continue
                elif isinstance(d, (bytes, bytearray, memoryview)):
                    if self.debuglevel > 0:
                        print('send:', type(d).__name__, len(d))
                    if not d:
                        continue
                else:
                    raise TypeError('unexpected %s' % (type(d).__name__,))
                if encode_chunked:
                    self._sendall(b'%X\r\n' % (len(d),))
                self._sendall(d)
                if encode_chunked:
                    self._sendall(b'\r\n')
        else:
            raise TypeError('unexpected %s' % (type(data).__name__,))
        
        if encode_chunked:
            if self.debuglevel > 0:
                print('send: terminating chunk')
            self._sendall(b'0\r\n\r\n')
    
    def getresponse(self, extra_headers=False, parse_cookies=False): # extra_headers and parse_cookies are an extension
        try:
            self._response = HTTPResponse(self._sock, self.debuglevel, self._method, self._url, extra_headers=extra_headers, parse_cookies=parse_cookies)
            return self._response
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
                if hasattr(ssl, 'SSLContext'):
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    context.verify_mode = ssl.CERT_NONE
                else:
                    context = None
            self._context = context
        
        def connect(self):
            super().connect()
            if self._context is None:
                self._sock = ssl.wrap_socket(self._sock, server_hostname=self.host)
            else:
                self._sock = self._context.wrap_socket(self._sock, server_hostname=self.host)

class HTTPException(Exception): pass
class NotConnected(HTTPException): pass
class BadStatusLine(HTTPException): pass
class RemoteDisconnected(BadStatusLine): pass

