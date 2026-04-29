# http/client_ish.py

import micropython, socket, time

HTTP_PORT = const(80)
HTTPS_PORT = const(443)

OK = const(200)
responses = {OK: "OK"}

# Connection states.
_CS_IDLE = const(0)
_CS_REQ_STARTED = const(1)
_CS_REQ_SENT = const(2)

# HTTPResponse.close() reasons: controls whether the socket is actually closed
# and whether the response is flagged as incomplete.
_CR_DONE = const(0)       # clean finish (or user close mid-body)
_CR_EOF = const(1)        # unexpected EOF; socket closed, possibly incomplete
_CR_MALFORMED = const(2)  # protocol violation; socket closed, incomplete

# Servers may 411 if these methods arrive without Content-Length.
_METHODS_EXPECTING_BODY = ("PATCH", "POST", "PUT")

_IMPORTANT_HEADERS = (
    b"connection",
    b"content-encoding",
    b"content-length",
    b"content-type",
    b"etag",
    b"keep-alive",
    b"location",
    b"retry-after",
    b"transfer-encoding",
    b"www-authenticate",
)

# MicroPython lacks iso-8859-1; use utf-8 throughout.
_DECODE_HEAD = const("utf-8")
_ENCODE_HEAD = const("utf-8")
_DECODE_BODY = const("utf-8")
_ENCODE_BODY = const("utf-8")

_BLANK = const(b"")
_CRLF = const(b"\r\n")

_MISSING = object()

class HTTPException(Exception): pass
class NotConnected(HTTPException): pass
class ImproperConnectionState(HTTPException): pass
class CannotSendRequest(ImproperConnectionState): pass
class CannotSendHeader(ImproperConnectionState): pass
class ResponseNotReady(ImproperConnectionState): pass
class BadStatusLine(HTTPException): pass
class RemoteDisconnected(ConnectionResetError, BadStatusLine): pass

def _iterable(obj):
    try:
        iter(obj)
        return True
    except TypeError:
        return False

@micropython.viper
def _lower(buf:ptr8, buflen:int, inplace:bool) -> int:
    # inplace=False: returns 1 if already lowercase, 0 otherwise.
    # inplace=True:  lowercases in place, returns 1.
    i = 0
    while i < buflen:
        b = buf[i]
        if 65 <= b <= 90:
            if inplace:
                buf[i] = b + 32
            else:
                return 0
        i += 1
    return 1

@micropython.viper
def _validate_ascii(buf:ptr8, buflen:int, deny_flags:int) -> int:
    # Rejects ctrl chars and bytes >= 127. deny_flags bit 0 also rejects space,
    # bit 1 also rejects comma.
    deny_space = (deny_flags & 1)
    deny_comma = (deny_flags & 2)
    i = 0
    while i < buflen:
        b = buf[i]
        if b < 32 or b >= 127:
            return 0
        if b == 32 and deny_space:
            return 0
        if b == 44 and deny_comma:
            return 0
        i += 1
    return 1

def _encode_and_validate(b, charset, *, deny_flags=0, force_bytes=False):
    valid = False
    if isinstance(b, (bytes, bytearray, memoryview)):
        pass
    elif isinstance(b, str):
        b = b.encode(charset)
    elif isinstance(b, int):
        b = str(b).encode(charset)
        valid = True
    else:
        raise TypeError("must be bytes-like or int")
    if (not valid) and _validate_ascii(b, len(b), deny_flags) == 0:
        raise ValueError("can't contain special characters")
    if force_bytes and isinstance(b, memoryview):
        b = bytes(b)
    return b

def create_connection(address, timeout=None):
    host, port = address
    for f, t, p, n, a in socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM):
        sock = None
        try:
            sock = socket.socket(f, t, p)
            try:
                if timeout != 0:
                    sock.settimeout(timeout)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except (AttributeError, OSError):
                pass
            sock.connect(a)
            return sock
        except Exception as e:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
            if not isinstance(e, OSError):
                raise e
    raise OSError(2)  # ENOENT

def parse_host_port(host, port, default_port=None):
    if port is None:
        i = host.rfind(':')
        j = host.rfind(']')
        if i > j:
            port_str = host[i+1:]
            if port_str == "":
                port = default_port
            elif not port_str[0].isdigit():
                raise ValueError("invalid port")
            else:
                port = int(port_str, 10)
            host = host[:i]
        else:
            port = default_port
    if host and host[0] == '[' and host[-1] == ']':
        host = host[1:-1]
    return (host, port)

def _normalize_key(key):
    # Strip surrounding whitespace, lowercase, return immutable bytes.
    if isinstance(key, str):
        key = key.encode(_ENCODE_HEAD)
    len_key = len(key)
    if len_key and (key[0] <= 32 or key[-1] <= 32):
        key = key.strip()
        len_key = len(key)
    if not _lower(key, len_key, False):
        if not isinstance(key, bytearray):
            key = bytearray(key)
        _lower(key, len_key, True)
    if not isinstance(key, bytes):
        key = bytes(key)
    return key

def parse_headers(sock, *, extra_headers=True):
    # Returns [(bytes_lowercase_key, bytes_value), ...].
    # extra_headers: True to keep all; False/empty to keep only _IMPORTANT_HEADERS;
    # or a container of additional keys to keep alongside _IMPORTANT_HEADERS.
    headers = []
    while True:
        line = sock.readline()
        if not line or line == _CRLF or line == b"\n":
            return headers
        if line.startswith((b' ', b'\t')):
            # obsolete RFC 2616 line folding
            if headers:
                k, v = headers.pop()
                v = v + b" " + line.strip()
                headers.append((k, v))
            continue
        sep = line.find(b':')
        if sep == -1:
            continue
        key, val = line[:sep], line[sep+1:]
        key = _normalize_key(key)
        if extra_headers is True or (extra_headers and key in extra_headers) or key in _IMPORTANT_HEADERS:
            headers.append((key, val.strip()))

class HTTPResponse:
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        return False
    
    def __init__(self, sock, debuglevel=0, method=None, url=None):
        self._sock = sock
        self.debuglevel = debuglevel
        self._method = method
        self.url = url
        self.version = None
        self.status = None
        self.reason = None
        self.headers = None
        self.chunked = False
        self.chunk_left = None
        self.will_close = True
        self.length = None
        self._bytes_read = 0
        self.incomplete = False
    
    def begin(self, *, extra_headers=True):
        self.version, self.status, self.reason = self._read_status()
        if self.debuglevel > 0:
            print("status:", repr(self.version), repr(self.status), repr(self.reason))
        
        if self.headers is not None:
            return
        
        self.headers = parse_headers(self._sock, extra_headers=extra_headers)
        if self.debuglevel > 0:
            for key, val in self.headers:
                print("header:", repr(key), "=", repr(val))
        
        transfer_encoding = self._getheader(b"transfer-encoding", b"")
        self.chunked = (b"chunked" in transfer_encoding.lower())
        self.chunk_left = None
        
        conn = self._getheader(b"connection", b"").lower()
        if self.version == 10:
            if b"keep-alive" in conn:
                self.will_close = False
            else:
                self.will_close = (self._getheader(b"keep-alive", _MISSING) is _MISSING)
        else:
            self.will_close = b"close" in conn
        
        # Content-Length is ignored when chunked (RFC 2616 S4.4 #3).
        self.length = None
        length = self._getheader(b"content-length", None)
        if length and not self.chunked:
            try:
                self.length = int(length, 10)
            except ValueError:
                pass
            else:
                if self.length < 0:
                    self.length = None
        self._bytes_read = 0
        
        # Responses that must have no body.
        if (100 <= self.status < 200
            or self.status == 204 or self.status == 304
            or self._method == "HEAD"):
            self.length = 0
            self.chunked = False
            self.chunk_left = None
        
        # Unknown framing on a keep-alive connection -> must close.
        if (not self.will_close and
            not self.chunked and
            self.length is None):
            self.will_close = True
    
    def _read_status(self):
        while True:
            line = self._sock.readline()
            if self.debuglevel > 0:
                print("status:", repr(line))
            if not line:
                raise RemoteDisconnected()
            if not line.startswith(b"HTTP/") or not line.endswith(b'\n'):
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
            
            if status < 100 or status > 999:
                raise BadStatusLine()
            
            if status != 100:
                break
            # Skip the 100 Continue's header block and re-read the real status.
            while True:
                line = self._sock.readline()
                if not line or line == _CRLF or line == b"\n":
                    break
                if self.debuglevel > 0:
                    print("header:", repr(line))
        
        if version == "HTTP/1.0":
            version = 10
        elif version.startswith("HTTP/1."):
            version = 11
        else:
            raise BadStatusLine()
        
        return version, status, reason
    
    def close(self, reason=_CR_DONE):
        sock = self._sock
        self._sock = None
        
        partial_body = (
            self.chunk_left is not None
            or (self.length is not None and self._bytes_read < self.length)
        )
        
        if reason == _CR_EOF:
            if partial_body:
                self.incomplete = True
            force_close = True
        elif reason == _CR_MALFORMED:
            self.incomplete = True
            force_close = True
        else:
            force_close = partial_body
        
        if sock is not None and (force_close or self.will_close):
            try:
                sock.close()
            except OSError:
                pass
    
    def isclosed(self):
        return self._sock is None
    
    @property
    def closed(self):
        return self.isclosed()
    
    def readinto(self, buf):
        if isinstance(buf, memoryview):
            return self._readinto(buf)
        else:
            return self._readinto(memoryview(buf))
    
    def _readinto(self, bmv):
        # Zero-sized: return immediately without touching the socket.
        if len(bmv) == 0:
            return 0
        if self.chunked:
            return self._read_chunked(bmv)
        else:
            return self._read_raw(bmv)
    
    def read(self, amt=None):
        res = self._read(amt)
        if res is None:
            return _BLANK
        if not isinstance(res, list):
            return res
        if len(res) == 0:
            return _BLANK
        if len(res) == 1:
            return res[0]
        return _BLANK.join(res)
    
    def _read(self, amt=None):
        # Zero-sized: return immediately without touching the socket.
        if amt == 0:
            return None
        if self.chunked:
            return self._read_chunked(amt)
        else:
            return self._read_raw(amt)
    
    def _read_chunked(self, arg=None):
        # Blocking socket assumed. Zero-sized arg is filtered upstream.
        # Input: memoryview (fills it; returns int), None/int (returns list[bytes]).
        arg_is_memoryview = isinstance(arg, memoryview)
        if arg_is_memoryview:
            res = arg
        else:
            parts = []
            if arg is not None:
                arg = int(arg)
                if arg < 0:
                    arg = None
        total = 0
        incomplete_read = False
        
        while True:
            if self.isclosed():
                break
            
            if self.chunk_left is None:
                line = self._sock.readline()
                if not line:
                    self.close(_CR_EOF)
                    incomplete_read = True
                    break
                sep = line.find(b';')
                if sep >= 0:
                    line = line[:sep]
                try:
                    chunk_size = int(line, 16)
                except ValueError:
                    self.close(_CR_MALFORMED)
                    incomplete_read = True
                    break
                if chunk_size < 0:
                    self.close(_CR_MALFORMED)
                    incomplete_read = True
                    break
                self.chunk_left = chunk_size
                if chunk_size == 0:
                    # Consume trailers until blank line.
                    while True:
                        line = self._sock.readline()
                        if not line or line == _CRLF or line == b"\n":
                            self.chunk_left = None
                            self.close(_CR_DONE)
                            break
                    break
            
            # self.chunk_left > 0 here, and caller's budget is > 0.
            if arg_is_memoryview:
                space = len(res) - total
                to_read = self.chunk_left
                if to_read > space:
                    to_read = space
                # Offset==0: hand sock.readinto the whole dest + nbytes cap,
                # saving a memoryview slice allocation.
                if total == 0:
                    nread = self._sock.readinto(res, to_read)
                else:
                    nread = self._sock.readinto(res[total:total+to_read])
                if not nread:
                    self.close(_CR_EOF)
                    incomplete_read = True
                    break
                self._bytes_read += nread
                total += nread
                self.chunk_left -= nread
            else:
                if arg is None:
                    to_read = self.chunk_left
                else:
                    remaining_req = arg - total
                    to_read = self.chunk_left
                    if to_read > remaining_req:
                        to_read = remaining_req
                chunk = self._sock.read(to_read)
                if not chunk:
                    self.close(_CR_EOF)
                    incomplete_read = True
                    break
                self._bytes_read += len(chunk)
                total += len(chunk)
                self.chunk_left -= len(chunk)
                parts.append(chunk)
            
            # Consume the CRLF after the chunk data when the chunk is done.
            if self.chunk_left == 0:
                line = self._sock.readline()
                if not line:
                    self.close(_CR_EOF)
                    incomplete_read = True
                    break
                if line != _CRLF and line != b"\n":
                    self.close(_CR_MALFORMED)
                    incomplete_read = True
                    break
                self.chunk_left = None
            
            # Exit when caller-supplied buffer/count is satisfied.
            if arg_is_memoryview:
                if total >= len(res):
                    break
            elif arg is not None:
                if total >= arg:
                    break
            # arg is None -> drain until the final 0-size chunk.
        
#        if incomplete_read:
#            raise IncompleteRead(self._bytes_read)
        
        if arg_is_memoryview:
            return total
        else:
            return parts
    
    def _read_raw(self, arg=None):
        # Blocking socket assumed. Zero-sized arg is filtered upstream.
        # Input modes:
        #   memoryview -> fill it, return int
        #   None       -> read all (bounded by CL if set), return bytes
        #   int > 0    -> read up to that many (bounded by CL), return bytes
        #   int < 0    -> treated as None
        arg_is_memoryview = isinstance(arg, memoryview)
        if arg_is_memoryview:
            res = arg
        elif arg is not None:
            arg = int(arg)
            if arg < 0:
                arg = None
        
        if self.isclosed():
            if arg_is_memoryview:
                return 0
            else:
                return None
        
        # Read-until-EOF framing: unbounded drain.
        if arg is None and self.length is None:
            chunk = self._sock.read()
            self._bytes_read += len(chunk)
            self.close(_CR_DONE)
            return chunk
        
        if self.length is None:
            if arg_is_memoryview:
                to_read = len(res)
            else:
                to_read = arg
        else:
            remaining = self.length - self._bytes_read
            if arg is None:
                to_read = remaining
            elif arg_is_memoryview:
                to_read = min(remaining, len(res))
            else:
                to_read = min(remaining, arg)
        
        if to_read < 0:
            # Already over CL -- body is untrustworthy.
            self.close(_CR_MALFORMED)
            if arg_is_memoryview:
                return 0
            else:
                return None
        
        chunk = None
        total = 0
        got_eof = False
        incomplete_read = False
        
        # to_read can be 0 when CL is already satisfied (e.g. HEAD, 204, 304).
        # Skip the socket call in that case; the CL-satisfied close block below
        # still runs.
        if to_read > 0:
            if arg_is_memoryview:
                nread = self._sock.readinto(res, to_read)
                if not nread:
                    got_eof = True
                else:
                    self._bytes_read += nread
                    total = nread
            else:
                chunk = self._sock.read(to_read)
                if not chunk:
                    got_eof = True
                    chunk = None
                else:
                    self._bytes_read += len(chunk)
            
            if got_eof:
                if self.length is not None and self._bytes_read < self.length:
                    self.close(_CR_EOF)
                    incomplete_read = True
                else:
                    self.close(_CR_DONE)
        
        if self.length is not None:
            if self._bytes_read == self.length:
                self.close(_CR_DONE)
            elif self._bytes_read > self.length:
                self.close(_CR_MALFORMED)
                incomplete_read = True
            elif arg is None:
                # Blocking "no short reads" means this path is unreachable
                # in practice; treat as incomplete if it ever happens.
                self.close(_CR_EOF)
                incomplete_read = True
        
#        if incomplete_read:
#            raise IncompleteRead(self._bytes_read, self.length)
        
        if arg_is_memoryview:
            return total
        else:
            return chunk
    
    def info(self):
        return self.headers
    
    @property
    def msg(self):
        return self.headers
    
    def geturl(self):
        return self.url
    
    def getcode(self):
        return self.status
    
    def getheaders(self):
        if self.headers is None:
            raise ResponseNotReady()
        return self.headers
    
    def getheader(self, key, default=None):
        # Duplicate header values are joined with b", ".
        if self.headers is None:
            raise ResponseNotReady()
        key = _normalize_key(key)
        numv = 0
        for k, v in self.headers:
            if k == key:
                if numv == 0:
                    vals = v
                    numv = 1
                elif numv == 1:
                    vals = [vals, v]
                    numv = 2
                else:
                    vals.append(v)
        if numv == 0:
            return default
        if numv == 1:
            return vals
        return b", ".join(vals)
    
    def _getheader(self, key, default=None):
        # Internal fast path: assumes key is already normalized bytes and
        # returns only the first match.
        for k, v in self.headers:
            if k == key:
                return v
        return default
    
    # Extension: yields fresh bytes chunks of up to chunk_size each.
    def iter_content(self, chunk_size=1024):
        chunk_size = int(chunk_size)
        if chunk_size <= 0:
            raise ValueError("chunk_size must be > 0")
        if self.length is not None:
            remaining = self.length - self._bytes_read
            if chunk_size > remaining:
                chunk_size = remaining
        buf = bytearray(chunk_size)
        bmv = memoryview(buf)
        while True:
            n = self._readinto(bmv)
            if n <= 0:
                break
            if n == chunk_size:
                yield bytes(buf)
            else:
                yield bytes(bmv[:n])
    
    # Extension: fills the caller's buffer, yields bytes-written counts.
    def iter_content_into(self, bmv):
        if not isinstance(bmv, memoryview):
            bmv = memoryview(bmv)
        while True:
            n = self._readinto(bmv)
            if n <= 0:
                break
            yield n
    
    def flush(self):
        pass
    
    def readable(self):
        return True

class HTTPConnection:
    _buffer_size = 1024   # request line + headers buffer, in bytes
    default_port = HTTP_PORT
    auto_open = True
    debuglevel = 0
    
    # Extension
    def __enter__(self):
        return self
    
    # Extension
    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        return False
    
    def __init__(self, host, port=None, timeout=None, source_address=None, blocksize=1024):
        self.host, self.port = parse_host_port(host, port, self.default_port)
        if not self.host:
            raise ValueError("invalid host")
        self.timeout = timeout
        self.blocksize = blocksize
        self.sock = None
        self.__response = None
        self.__state = _CS_IDLE
        self._auto_open = False
        self._sent_data = False
        if self._buffer_size:
            self._buffer = memoryview(bytearray(self._buffer_size))
        else:
            self._buffer = None
        self._filled = 0
        self._method = None
        self._url = None
    
    def set_debuglevel(self, level):
        self.debuglevel = level
    
    def connect(self):
        self.sock = create_connection((self.host, self.port), self.timeout)
    
    def close(self):
        self.__state = _CS_IDLE
        self._filled = 0
        try:
            sock = self.sock
            self.sock = None
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        finally:
            response = self.__response
            self.__response = None
            if response is not None:
                response.close(_CR_EOF)
    
    # Derived from CPython.
    def request(self, method, url, body=None, headers=None, *, encode_chunked=False):
        have_accept_encoding = False
        have_content_length = False
        have_host = False
        have_transfer_encoding = False
        
        if headers is not None:
            # Materialize headers once so a generator isn't consumed twice.
            if hasattr(headers, "items") and callable(headers.items):
                items = headers.items()
            else:
                items = headers
            if not isinstance(items, (list, tuple)):
                items = list(items)
            for key, val in items:
                key = _normalize_key(key)
                if key == b"accept-encoding":
                    have_accept_encoding = True
                elif key == b"content-length":
                    have_content_length = True
                elif key == b"host":
                    have_host = True
                elif key == b"transfer-encoding":
                    have_transfer_encoding = True
        
        self.putrequest(method, url, skip_accept_encoding=have_accept_encoding, skip_host=have_host)
        
        if isinstance(body, str):
            body = body.encode(_ENCODE_BODY)
        
        if not have_content_length:
            if not have_transfer_encoding:
                # Auto-detect Content-Length or fall back to chunked.
                encode_chunked = False
                if body is None:
                    if self._method in _METHODS_EXPECTING_BODY:
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
                    self.putheader(b"Content-Length", content_length)
        else:
            encode_chunked = False
        
        if headers is not None:
            self.putheaders(items)
        self.endheaders(body, encode_chunked=encode_chunked)
    
    # Derived from CPython.
    def putrequest(self, method, url, skip_host=False, skip_accept_encoding=False):
        if self.__response is not None:
            if not self.__response.isclosed():
                raise CannotSendRequest()
            self.__response = None
        if self.__state != _CS_IDLE:
            raise CannotSendRequest()
        self.__state = _CS_REQ_STARTED
        
        self._auto_open = self.auto_open
        self._sent_data = False
        self._filled = 0
        
        method = _encode_and_validate(method, "ascii", deny_flags=1, force_bytes=True)
        if method == b"GET":
            self._method = "GET"
        else:
            self._method = method.upper().decode("ascii")
        self._url = url
        url = _encode_and_validate(url, _ENCODE_HEAD, deny_flags=1) if url else b"/"
        
        self._putheaderparts(False, method, b" ", url, b" HTTP/1.1\r\n")
        
        if not skip_host:
            host = self.host
            # Bare IPv6 -> bracket it for the Host header.
            if ':' in host and not host.startswith('['):
                host = "[%s]" % (host,)
            if self.port == self.default_port:
                self.putheader(b"Host", host)
            else:
                self.putheader(b"Host", "%s:%d" % (host, self.port))
        if not skip_accept_encoding:
            self._putheaderparts(False, b"Accept-Encoding: identity\r\n")
    
    # Extension
    def putheaders(self, headers):
        if hasattr(headers, "items") and callable(headers.items):
            items = headers.items()
        elif not isinstance(headers, (list, tuple)):
            items = list(headers)
        else:
            items = headers
        for key, val in items:
            self.putheader(key, val)
    
    def putheader(self, header, *values):
        if isinstance(header, str):
            header = header.encode(_ENCODE_HEAD)
        if len(values) == 1:
            self._putheaderparts(False, header, b": ", _encode_and_validate(values[0], _ENCODE_HEAD), _CRLF)
        else:
            self._putheaderparts(False, header, b": ", b", ".join(_encode_and_validate(v, _ENCODE_HEAD, deny_flags=2) for v in values), _CRLF)
    
    def _putheaderparts(self, last, *parts):
        # Buffers header bytes until full or `last` flushes.
        if self.__state != _CS_REQ_STARTED or self.__response is not None:
            raise CannotSendHeader()
        
        if self._buffer is None:
            self._send_raw(_BLANK.join(parts))
        else:
            for part in parts:
                len_part = len(part)
                if len_part >= self._buffer_size:
                    if self._filled:
                        self._send_raw(self._buffer[:self._filled])
                        self._filled = 0
                    self._send_raw(part)
                elif self._filled + len_part <= self._buffer_size:
                    self._buffer[self._filled:self._filled+len_part] = part
                    self._filled += len_part
                else:
                    self._send_raw(self._buffer[:self._filled])
                    self._buffer[:len_part] = part
                    self._filled = len_part
        
        if last and self._filled:
            self._send_raw(self._buffer[:self._filled])
            self._filled = 0
    
    def endheaders(self, message_body=None, *, encode_chunked=False):
        if self.__state != _CS_REQ_STARTED or self.__response is not None:
            raise CannotSendHeader()
        
        self._putheaderparts(True, _CRLF)
        self._auto_open = False
        self.__state = _CS_REQ_SENT
        if message_body is not None:
            self.send(message_body, encode_chunked=encode_chunked)
    
    def _send_raw(self, data):
        # Blocking socket assumed. On first call of a request, may transparently
        # (re)connect if an existing keep-alive socket is dead.
        if not data:
            return
        
        if self._auto_open and not self._sent_data:
            try:
                if self.sock is not None:
                    self.sock.sendall(data)
                    if data:
                        self._sent_data = True
                    return
            except OSError:
                try: self.sock.close()
                except Exception: pass
                self.sock = None
            try:
                self.connect()
            except OSError:
                raise NotConnected()
            self.sock.sendall(data)
            self._sent_data = True
            return
        
        if self.sock is None:
            raise NotConnected()
        self.sock.sendall(data)
        self._sent_data = True
    
    def _send_chunk(self, data):
        # None -> final (terminating) chunk.
        if data is None:
            self._send_raw(b"0\r\n\r\n")
        if not data:
            return
        self._send_raw(b"%X\r\n" % (len(data),))
        self._send_raw(data)
        self._send_raw(_CRLF)
    
    # encode_chunked and final_chunk are extensions beyond CPython.
    def send(self, data, *, encode_chunked=False, final_chunk=True):
        send = self._send_chunk if encode_chunked else self._send_raw
        
        if isinstance(data, str):
            data = data.encode(_ENCODE_BODY)
        
        if data is None:
            if self.debuglevel > 0:
                print("send: None")
            pass
        
        elif isinstance(data, (bytes, bytearray, memoryview)):
            if self.debuglevel > 0:
                print("send:", type(data).__name__, len(data))
            if data:
                send(data)
        
        elif hasattr(data, "readinto"):
            if self.debuglevel > 0:
                print("send: readinto()")
            buf = bytearray(self.blocksize)
            while True:
                n = data.readinto(buf)
                if n is None:
                    time.sleep_ms(1)
                    continue
                if not n:
                    break
                send(buf[:n])
        
        elif hasattr(data, "read"):
            if self.debuglevel > 0:
                print("send: read()")
            while True:
                d = data.read(self.blocksize)
                if isinstance(d, str):
                    d = d.encode(_ENCODE_BODY)
                if d is None:
                    time.sleep_ms(1)
                    continue
                if not d:
                    break
                send(d)
        
        elif callable(data):
            if self.debuglevel > 0:
                print("send: callable!")
            for d in data():
                if isinstance(d, str):
                    d = d.encode(_ENCODE_BODY)
                if d is not None:
                    send(d)
        
        elif _iterable(data):
            if self.debuglevel > 0:
                print("send: iterable!")
            for d in data:
                if isinstance(d, str):
                    d = d.encode(_ENCODE_BODY)
                if d is not None:
                    send(d)
        
        else:
            raise TypeError("unexpected data")
        
        if encode_chunked and final_chunk:
            if self.debuglevel > 0:
                print("send: terminator")
            send(None)
    
    def getresponse(self, **kwargs):
        if self.__response is not None and self.__response.isclosed():
            self.__response = None
        if self.__state != _CS_REQ_SENT or self.__response is not None:
            raise ResponseNotReady()
        
        try:
            response = HTTPResponse(self.sock, self.debuglevel, self._method, self._url)
            response.begin(**kwargs)
            self.__state = _CS_IDLE
            if response.will_close:
                # Ownership transferred to the response; it will close.
                self.sock = None
                self.__response = None
            else:
                self.__response = response
            return response
        except Exception:
            self.close()
            raise
    
    def detach(self):
        # Hand the socket back to the caller and reset our state.
        if self.__response is not None:
            sock = self.__response._sock
            self.__response._sock = None
            self.__response = None
        else:
            sock = self.sock
        self.sock = None
        self.__state = _CS_IDLE
        return sock

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
            self._context = context
        
        def connect(self):
            super().connect()
            raw = self.sock
            
            # Skip SNI for IP literals (RFC 6066).
            hostname = None
            if not isinstance(self.host, str):
                pass
            elif all(c.isdigit() or c == '.' for c in self.host):
                pass
            elif ':' in self.host:
                pass
            else:
                hostname = self.host
            
            try:
                if self._context is None:
                    self.sock = ssl.wrap_socket(raw, server_hostname=hostname)
                else:
                    self.sock = self._context.wrap_socket(raw, server_hostname=hostname)
            except Exception:
                self.sock = None
                try:
                    raw.close()
                except OSError:
                    pass
                raise
