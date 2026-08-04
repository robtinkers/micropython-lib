# http/clientish.py
#
# Serious HTTP for tiny devices.

import micropython, socket, errno, gc

_COMPATISH_EXCEPTIONS = const(0)
_COMPATISH_MOST_METHODS = const(0)
_COMPATISH_READ_RETURNS_BYTES = const(0)
_COMPATISH_ALL_HEADERS = const(0)
_COMPATISH_DECODE_HEADERS = const(0)

_EXTRA_METHODS = const(1)
_ITERATE_HEADERS = const(1)
_RECYCLE_BUFFERS = const(1)
_SSL_ENABLED = const(1)

_DEFAULT_TIMEOUT = const(10)
_GC_FREE_THRESHOLD = const(32768)
_READ_BLOCK_SIZE = const(1024)
_READ_BLOCK_SIZE_HEXCRLF = const(b"400\r\n")
_REQUEST_HEAD_SIZE = const(256)

HTTP_PORT = const(80)
HTTPS_PORT = const(443)
OK = const(200)

ENONET = getattr(errno, "ENONET", 64)
ENETDOWN = getattr(errno, "ENETDOWN", 100)
ENETUNREACH = getattr(errno, "ENETUNREACH", 101)
EHOSTDOWN = getattr(errno, "EHOSTDOWN", 112)
EHOSTUNREACH = getattr(errno, "EHOSTUNREACH", 113)

_RF_HOST = const(1)
_RF_CONNECTION_CLOSE = const(4)
_RF_CONTENT_LENGTH = const(8)
_RF_ACCEPT_ENCODING = const(16)
_RF_TRANSFER_ENCODING = const(32)
_RF_TRANSFER_CHUNKED = const(64)

_CS_IDLE = const(0)
_CS_REQUEST_BUILDING = const(1)
_CS_REQUEST_HEAD_OPEN = const(2)
_CS_REQUEST_BODY_OPEN = const(3)
_CS_RESPONSE_CREATING = const(4)
_CS_RESPONSE_ACTIVE = const(5)
_CS_RESPONSE_REUSABLE = const(6)

_ACCEPT_ENCODING = b"Accept-Encoding"
_CONNECTION = b"Connection"
_CONTENT_LENGTH = b"Content-Length"
_HOST = b"Host"
_SET_COOKIE = b"Set-Cookie"
_TRANSFER_ENCODING = b"Transfer-Encoding"

_CHUNKED = b"chunked"
_CLOSE = b"close"

_BUFFER_TYPES = (bytes, bytearray, memoryview)

_KEEP_RESPONSE_HEADERS = (
    b"Content-Type",
    _CONTENT_LENGTH,
    _TRANSFER_ENCODING,
    _CONNECTION,
    _SET_COOKIE,
    b"Location",
    b"ETag",
    b"Retry-After",
)

class HTTPException(Exception): pass

if _COMPATISH_EXCEPTIONS:
    error = HTTPException

class ImproperConnectionState(HTTPException): pass
class CannotSendRequest(ImproperConnectionState): pass
class CannotSendHeader(ImproperConnectionState): pass
class ResponseNotReady(ImproperConnectionState): pass
class NotConnected(ImproperConnectionState): pass

class BadStatusLine(HTTPException):
    def __init__(self, line):
        if _COMPATISH_DECODE_HEADERS and isinstance(line, _BUFFER_TYPES):
            line = decode_latin1(line)
        self.errno = None
        self.args = line,
        self.line = line

if _COMPATISH_EXCEPTIONS:
    class UnknownProtocol(HTTPException):
        def __init__(self, version):
            if _COMPATISH_DECODE_HEADERS and isinstance(version, _BUFFER_TYPES):
                version = decode_latin1(version)
            self.errno = None
            self.args = version,
            self.version = version
else:
    class UnknownProtocol(BadStatusLine): pass

class RequestLengthMismatch(HTTPException):
    def __init__(self, observed, expected):
        self.errno = None
        self.args = (observed, expected)
        self.observed = observed
        self.expected = expected

class TransportError(HTTPException):
    def __init__(self, error, message, _count=None, _length=None, _status=None):
        self.errno = error
        self.message = message
        self.status = _status
        if _COMPATISH_EXCEPTIONS:
            self.partial = _count
            if type(_count) is int and type(_length) is int:
                self.expected = _length - _count
            else:
                self.expected = None
            self.args = _count,
        else:
            self.count = _count
            self.length = _length
            self.args = (error, message)

    def __str__(self):
        return self.__class__.__name__ + "(" + repr(self.errno) + ", " + repr(self.message) + ", ...)"

    __repr__ = __str__

class ConnectError(TransportError): pass
class IncompleteWrite(TransportError): pass
class IncompleteRead(TransportError): pass

if _COMPATISH_EXCEPTIONS:
    class RemoteDisconnected(BadStatusLine):
        def __init__(self):
            super().__init__(None)
    class InvalidURL(HTTPException): pass
else:
    class RemoteDisconnected(IncompleteRead):
        def __init__(self):
            super().__init__(None, None)
    class InvalidURL(ValueError): pass

@micropython.viper
def _equals_ci(a: ptr8, b: ptr8, length: int) -> int:
    i = 0
    while i < length:
        x = a[i]
        y = b[i]
        if x != y:
            if 65 <= x and x <= 90:
                x += 32
            if 65 <= y and y <= 90:
                y += 32
            if x != y:
                return 0
        i += 1
    return 1

@micropython.viper
def _endswith_lc(haystack: ptr8, haystack_len: int, needle: ptr8, needle_len: int) -> int:
    if haystack_len < needle_len:
        return 0
    while needle_len:
        haystack_len -= 1
        needle_len -= 1
        x = haystack[haystack_len]
        y = needle[needle_len]
        if x != y:
            if 65 <= x and x <= 90:
                x += 32
            if x != y:
                return 0
    return 1

if _EXTRA_METHODS:

    @micropython.viper
    def _startswith_lc(haystack: ptr8, haystack_len: int, needle: ptr8, needle_len: int) -> int:
        if haystack_len < needle_len:
            return 0
        i = 0
        while i < needle_len:
            x = haystack[i]
            y = needle[i]
            if x != y:
                if 65 <= x and x <= 90:
                    x += 32
                if x != y:
                    return 0
            i += 1
        return 1

@micropython.viper
def _contains_lc(haystack: ptr8, haystack_len: int, needle: ptr8, needle_len: int) -> int:
    if needle_len == 0:
        return 1
    if haystack_len < needle_len:
        return 0
    haystack_len -= needle_len
    first = needle[0]
    i = 0
    while i <= haystack_len:
        x = haystack[i]
        if x != first:
            if x < 65 or x > 90 or x + 32 != first:
                i += 1
                continue
        j = 1
        while j < needle_len:
            x = haystack[i + j]
            y = needle[j]
            if x != y:
                if x < 65 or x > 90 or x + 32 != y:
                    break
            j += 1
        if j == needle_len:
            return 1
        i += 1
    return 0

@micropython.viper
def _validate(haystack: ptr8, haystack_len: int, strict: int) -> int:
    i = 0
    while i < haystack_len:
        x = haystack[i]
        if x <= 32 and (strict or x == 10 or x == 13):
            return 0
        i += 1
    return 1

def _encode_and_validate(x, strict=0):
    if x is None:
        return None
    if isinstance(x, str):
        x = x.encode()
    elif type(x) is int:
        x = b"%d" % x
    elif not isinstance(x, _BUFFER_TYPES):
        x = str(x).encode()
    if not _validate(x, len(x), strict):
        return None
    if not strict or type(x) is bytes:
        return x
    return bytes(x)

if _COMPATISH_DECODE_HEADERS:

    @micropython.viper
    def _latin1_to_utf8(src: ptr8, srclen: int, dst: ptr8) -> int:
        write = int(dst) != 0
        dstlen = 0
        i = 0
        while i < srclen:
            b = src[i]
            i += 1
            if b < 128:
                if write:
                    dst[dstlen] = b
                dstlen += 1
            else:
                if write:
                    dst[dstlen]   = 0xC0 | (b >> 6)
                    dst[dstlen+1] = 0x80 | (b & 0x3F)
                dstlen += 2
        return dstlen

    def decode_latin1(buf, default=None):
        if buf is None:
            return default
        if not isinstance(buf, _BUFFER_TYPES):
            raise TypeError("buffer type required")
        buflen = len(buf)
        if buflen == 0:
            return ""
        utf8len = _latin1_to_utf8(buf, buflen, 0)
        if utf8len == buflen:
            return buf.decode()
        utf8out = bytearray(utf8len)
        _latin1_to_utf8(buf, buflen, utf8out)
        return utf8out.decode()

def _errno(err):
    return err or 0

def _close_quietly(sock):
    if sock is not None:
        try:
            sock.close()
        except Exception:
            pass

def create_connection(address, timeout=None, *, resolver=None):
    if resolver is None:
        resolver = socket.getaddrinfo
    try:
        infos = resolver(address[0], address[1], 0, socket.SOCK_STREAM)
    except OSError as e:
        raise OSError(EHOSTDOWN, str(e))

    exc = None
    for info in infos:
        sock = None
        try:
            sock = socket.socket(info[0], info[1], info[2])
            if timeout != 0:
                sock.settimeout(timeout)
            try:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except (AttributeError, OSError):
                pass
            sock.connect(info[4])
            return sock
        except OSError as e:
            exc = e
            _close_quietly(sock)
        except Exception:
            _close_quietly(sock)
            raise
    if exc is None:
        raise OSError(EHOSTUNREACH, "host unreachable")
    raise exc

def _parse_hostport_from_url(url):
    if url.startswith(b"http://"):
        start = 7
    elif url.startswith(b"https://"):
        start = 8
    else:
        return None
    end = len(url)

    for separator in (b"/", b"?", b"#"):
        pos = url.find(separator, start)
        if 0 <= pos < end:
            end = pos

    pos = url.rfind(b"@", start, end)
    if pos >= 0:
        start = pos + 1

    return url[start:end]

def _parse_status_line(sock):
    while True:
        first = sock.read(1)
        if not first:
            raise RemoteDisconnected()
        if first == b"\r" or first == b"\n":
            continue
        if first != b"H":
            raise BadStatusLine(first + b"...")
        line = sock.readline()
        if not line.startswith(b"TTP/") or line[-1] != 10:
            break

        status = line.split(None, 2)
        if len(status) == 3:
            version, status, reason = status
        elif len(status) == 2:
            version, status = status
            reason = b""
        else:
            break

        if version == b"TTP/1.0":
            version = 10
        elif version.startswith(b"TTP/1."):
            version = 11
        elif _COMPATISH_EXCEPTIONS:
            raise UnknownProtocol(first + version)
        else:
            raise UnknownProtocol(first + line)

        if len(status) != 3 or not status.isdigit():
            break
        status = int(status, 10)
        if status < 100:
            break

        return version, status, reason

    raise BadStatusLine(first + line)

def _parse_headers(sock, status, all_headers, and_cookies):
    if all_headers is None:
        all_headers = bool(_COMPATISH_ALL_HEADERS)
    if and_cookies is None:
        and_cookies = all_headers

    headers = []

    while True:
        line = None
        line = sock.readline()
        if not line:
            raise IncompleteRead(None, "EOF in response headers", None, None, status)
        if line[-1] != 10:
            raise IncompleteRead(None, "unterminated response header", None, None, status)
        if line == b"\r\n" or line == b"\n":
            return headers
        if line[0] <= 32:
            continue

        pos = line.find(b":")
        if pos == -1:
            continue

        for name in _KEEP_RESPONSE_HEADERS:
            if len(name) == pos and _equals_ci(line, name, pos):
                break
        else:
            name = None

        if name is None:
            if not all_headers:
                continue
            name = line[:pos]
        elif name is _SET_COOKIE and not and_cookies:
            continue

        pos += 1
        end = len(line)
        while pos < end and line[pos] <= 32: pos += 1
        while end > pos and line[end - 1] <= 32: end -= 1
        headers.append((name, line[pos:end]))

def _derive_response_framing(method, version, status, headers):
    http10 = (version == 10)
    length = None
    chunked = None
    reusable = None

    for key, val in headers:
        if key is _CONTENT_LENGTH:
            try:
                val = int(val, 10)
                if val < 0:
                    val = -1
            except (OverflowError, ValueError):
                val = -1
            if length is None:
                length = val
            elif length != val:
                length = -1

        elif key is _CONNECTION:
            if reusable is not False:
                if http10:
                    reusable = (len(val) == 10 and _equals_ci(val, b"keep-alive", 10))
                else:
                    reusable = not _contains_lc(val, len(val), _CLOSE, 5)

        elif key is _TRANSFER_ENCODING:
            chunked = bool(_endswith_lc(val, len(val), _CHUNKED, 7))

    if reusable is None:
        reusable = not http10

    if chunked and (http10 or length is not None):
        reusable = False

    if status == 101:
        return False, 0, False

    if method == b"CONNECT" and 200 <= status < 300:
        return False, None, False

    if status < 200 or status == 204:
        return False, 0, (
            reusable and chunked is None
            and (length is None or (length == 0 and status == 204)))

    if method == b"HEAD" or status == 304:
        return False, 0, (reusable and length != -1)

    if chunked is True:
        return True, None, reusable

    if chunked is False:
        if length is not None and length >= 0:
            return False, length, False
        return False, None, False

    if length == -1:
        return False, None, False

    return False, length, (reusable and length is not None)

class HTTPResponse:
    _chunk_left = None

    def __init__(self, owner, sock, method, url, version, status, reason, headers, chunked, length):
        if owner is None and sock is not None:
            raise ValueError("socket owner required")
        self._owner = owner
        self._sock = sock
        if _COMPATISH_DECODE_HEADERS:
            url = decode_latin1(url)
            reason = decode_latin1(reason)
        self.method = method
        self.url = url
        self.version = version
        self.status = status
        if _COMPATISH_MOST_METHODS:
            self.code = status
        self.reason = reason.rstrip()
        self._headers = headers
        self._chunked = chunked
        self._length = length
        self._count = 0

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def close(self):
        self._release_socket(self._count == self._length)

    def detach(self):
        sock = self._sock
        if sock is None:
            raise NotConnected()
        owner = self._owner
        self._sock = self._owner = None
        if owner is not None:
            owner._release_response(self, None, None)
        return sock

    if _EXTRA_METHODS:

        def drain(self, buf=None):
            if buf is None:
                size = _READ_BLOCK_SIZE
                if self._length is not None:
                    size = min(size, self._length - self._count)
                    if size <= 0:
                        self.close()
                        return
                buf = bytearray(size)
            elif not buf:
                raise ValueError("empty buffer")
            while self.readinto(buf):
                pass

    def getheader(self, name, default=None):
        name = _encode_and_validate(name)
        if name is None:
            return default
        len_name = len(name)
        result = None
        for key, val in self._headers:
            if len(key) != len_name or not _equals_ci(key, name, len_name):
                continue
            if result is None:
                result = val
            else:
                result += b", " + val
        if result is None:
            return default
        if _COMPATISH_DECODE_HEADERS:
            result = decode_latin1(result)
        return result

    def getheaders(self):
        if _COMPATISH_DECODE_HEADERS:
            if _ITERATE_HEADERS:
                return ((decode_latin1(k), decode_latin1(v)) for k,v in self._headers)
            else:
                return [(decode_latin1(k), decode_latin1(v)) for k,v in self._headers]
        else:
            if _ITERATE_HEADERS:
                return iter(self._headers)
            else:
                return self._headers

    def read(self, amt=None):
        return self._read_body(None, amt)

    def readinto(self, buf):
        if buf is None:
            raise TypeError("buffer required")
        return self._read_body(buf, None)

    def _read_body(self, buf, amt):
        try:
            sock = self._sock
            into = buf is not None

            if sock is None:
                if self._length is not None and self._count >= self._length:
                    return 0 if into else b""
                raise NotConnected()

            if into:
                if not buf:
                    return 0
                amt = len(buf)
            elif amt is not None and amt < 0:
                amt = None

            if amt == 0:
                return 0 if into else b""

            if self._length is not None:
                n = self._length - self._count
                if n <= 0:
                    self.close()
                    return 0 if into else b""
                if amt is None or n < amt:
                    amt = n

            if into and not self._chunked:
                n = sock.readinto(buf, amt)
                if not n:
                    if self._length is None:
                        self._length = self._count
                        self.close()
                        return 0
                    self._abort_read("EOF in response body")

                self._count += n
                if self._length is not None and self._count >= self._length:
                    self.close()
                return n

            out = buf if into else (b"" if amt is None else bytearray(amt))
            total = 0

            if amt is not None:
                data = out if isinstance(out, memoryview) else memoryview(out)

            while amt is None or total < amt:
                if into:
                    n = amt - total
                elif amt is None:
                    n = _READ_BLOCK_SIZE
                else:
                    n = min(amt - total, _READ_BLOCK_SIZE)

                if self._chunked:
                    n = min(n, self._get_chunk_left())
                    if n == 0:
                        break

                if amt is None:
                    data = sock.read(n)
                    n = len(data)
                else:
                    n = sock.readinto(data if not total else data[total:], n)

                if not n:
                    if self._chunked:
                        self._abort_read("EOF in chunk data")
                    if self._length is not None:
                        self._abort_read("EOF in response body")
                    self._length = self._count
                    self.close()
                    break

                self._count += n
                total += n

                if self._chunked:
                    self._chunk_left -= n
                elif self._length is not None and self._count >= self._length:
                    self.close()

                if amt is None:
                    if not out:
                        out = data
                    else:
                        if type(out) is bytes:
                            out = bytearray(out)
                        out.extend(data)
                    data = None

            if into:
                return total

            if amt is not None and total < amt:
                data = None
                del out[total:]

            if _COMPATISH_READ_RETURNS_BYTES and type(out) is not bytes:
                out = bytes(out)

            return out
        except MemoryError:
            out = data = sock = None
            self._release_socket(False)
            gc.collect()
            raise
        except OverflowError:
            self._release_socket(False)
            raise
        except OSError as e:
            self._abort_read("socket read failed", _errno(e.errno))

    def _get_chunk_left(self):
        while True:
            if self._chunk_left is None:
                line = self._sock.readline()
                if not line:
                    self._abort_read("EOF before chunk size")
                pos = line.find(b";")
                try:
                    if pos >= 0:
                        line = line[:pos]
                    size = int(line, 16)
                    if size < 0:
                        self._abort_read("negative chunk size")
                except (OverflowError, ValueError):
                    self._abort_read("invalid chunk size")
                if size > 0:
                    self._chunk_left = size
                    return size
                while True:
                    line = self._sock.readline()
                    if (line == b"\r\n" or line == b"\n"):
                        self._length = self._count
                        self.close()
                        return 0
                    if not line:
                        self._abort_read("EOF in chunk trailers")
            elif self._chunk_left == 0:
                line = self._sock.readline()
                if not line:
                    self._abort_read("EOF before chunk terminator")
                if not (line == b"\r\n" or line == b"\n"):
                    self._abort_read("invalid chunk terminator")
                self._chunk_left = None
            else:
                return self._chunk_left

    def _abort_read(self, message, error=None):
        self._release_socket(False)
        raise IncompleteRead(error, message, self._count, self._length, self.status)

    def _release_socket(self, complete):
        sock = self._sock
        owner = self._owner
        self._sock = self._owner = None
        if owner is not None:
            owner._release_response(self, sock, complete)

    @property
    def closed(self):
        return self._sock is None

    if _COMPATISH_MOST_METHODS:
        def isclosed(self):
            return self._sock is None

        def fileno(self):
            return self._sock.fileno()

        def readable(self):
            return True

        def info(self):
            return self.headers

        def geturl(self):
            return self.url

        def getcode(self):
            return self.status

        def flush(self):
            pass

        def begin(self, *, _max_headers=None):
            pass

        @property
        def headers(self):
            return self

        msg = headers
        get = getheader
        items = getheaders

        def get_all(self, name, default=None):
            name = _encode_and_validate(name)
            if name is None:
                return default
            length = len(name)
            values = None
            for key, value in self._headers:
                if len(key) == length and _equals_ci(key, name, length):
                    if values is None:
                        values = []
                    if _COMPATISH_DECODE_HEADERS:
                        value = decode_latin1(value)
                    values.append(value)
            return default if values is None else values

        @property
        def chunked(self):
            return self._chunked

        @property
        def length(self):
            if self._length is None:
                return None
            return max(0, self._length - self._count)

class HTTPConnection:
    response_class = HTTPResponse
    default_port = HTTP_PORT
    timeout = _DEFAULT_TIMEOUT
    _network = None

    def __init__(self, host, port=None, timeout=None, *, network=None):
        the_host = _encode_and_validate(host, 1)
        if not the_host:
            raise InvalidURL(host)

        hostaddr = the_host
        hostname = None
        colons = the_host.count(b":")

        if the_host.startswith(b"["):
            sep = the_host.find(b"]")
            if sep == -1:
                raise InvalidURL(host)
            if sep + 1 < len(the_host):
                if the_host[sep + 1] != 58:
                    raise InvalidURL(host)
                if port is None and sep + 2 < len(the_host):
                    try: port = int(the_host[sep + 2:], 10)
                    except ValueError: port = -1
                the_host = the_host[:sep + 1]
            hostaddr = the_host[1:sep]
        elif colons == 1:
            sep = the_host.find(b":")
            if sep + 1 < len(the_host):
                if port is None:
                    try: port = int(the_host[sep + 1:], 10)
                    except ValueError: port = -1
            hostaddr = the_host[:sep]
            the_host = hostaddr
        elif colons:
            the_host = b"[%s]" % the_host

        if not hostaddr:
            raise InvalidURL(host)
        if hostaddr.find(b":") == -1:
            for b in hostaddr:
                if not (b == 46 or (48 <= b <= 57)):
                    hostname = the_host
                    break

        if port is None:
            port = self.default_port
        if not isinstance(port, int):
            raise TypeError("port must be int")
        if not (0 <= port <= 65535):
            raise TypeError("port invalid")

        if port == self.default_port:
            hostport = the_host
        else:
            hostport = b"%s:%d" % (the_host, port)

        self.host = hostaddr
        self._hostname = hostname
        self._hostport = hostport
        self.port = port

        if timeout is not None:
            self.timeout = timeout
        if network is not None:
            self._network = network
        self._sock = None
        self._head = None
        self._reset_request()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def connect(self):
        if self._state != _CS_IDLE:
            raise CannotSendRequest()
        self.close()
        self._open_socket()

    def close(self):
        _close_quietly(self.detach())

    def detach(self):
        if self._resp is not None:
            return self._resp.detach()
        sock, self._sock = self._sock, None
        self._reset_request()
        return sock

    def request(self, method, url, body=None, headers=None, *, encode_chunked=None):
        self.putrequest(method, url)
        try:
            if headers is not None:
                if isinstance(headers, dict):
                    headers = headers.items()
                for key, value in headers:
                    self.putheader(key, value)
        except Exception:
            self._reset_request()
            raise

        self.endheaders(body, encode_chunked=encode_chunked)

    def putrequest(self, method, url, skip_host=False, skip_accept_encoding=False):
        if self._state != _CS_IDLE:
            raise CannotSendRequest()

        method = _encode_and_validate(method, 1)
        if not method:
            raise ValueError("invalid method")
        if not method.isupper():
            method = method.upper()

        if url:
            valid_url = _encode_and_validate(url, 1)
        else:
            valid_url = b"/"
        if not valid_url:
            raise InvalidURL(url)

        self._state = _CS_REQUEST_BUILDING
        try:
            self.method = method
            self.url = valid_url

            if self._head is None:
                self._head = bytearray(_REQUEST_HEAD_SIZE)
                self._head[:] = b""
            self._head.extend(method)
            self._head.extend(b" ")
            self._head.extend(valid_url)
            self._head.extend(b" HTTP/1.1\r\n")

            if skip_host:
                self._flags |= _RF_HOST
            if skip_accept_encoding:
                self._flags |= _RF_ACCEPT_ENCODING
        except MemoryError:
            self._head = None
            self._reset_request()
            gc.collect()
            raise

    def putheader(self, name, value):
        if self._state != _CS_REQUEST_BUILDING:
            raise CannotSendHeader()

        name = _encode_and_validate(name)
        if name is None:
            raise ValueError("invalid header name")
        if value is not None:
            value = _encode_and_validate(value)
            if value is None:
                raise ValueError("invalid header value")
            try:
                self._append_header(name, value)
            except MemoryError:
                self._head = None
                self._reset_request()
                gc.collect()
                raise

        len_name = len(name)
        length = self._length
        flags = self._flags

        if len_name == 4 and _equals_ci(name, _HOST, 4):
            flags |= _RF_HOST
        elif len_name == 10 and _equals_ci(name, _CONNECTION, 10):
            if value is not None and _contains_lc(value, len(value), _CLOSE, 5):
                flags |= _RF_CONNECTION_CLOSE
        elif len_name == 14 and _equals_ci(name, _CONTENT_LENGTH, 14):
            flags |= _RF_CONTENT_LENGTH
            if value is not None:
                try:
                    value = int(value, 10)
                except (OverflowError, TypeError, ValueError):
                    value = -1
                if value >= 0 and (length is None or length == value):
                    length = value
                else:
                    length = -1
        elif len_name == 15 and _equals_ci(name, _ACCEPT_ENCODING, 15):
            flags |= _RF_ACCEPT_ENCODING
        elif len_name == 17 and _equals_ci(name, _TRANSFER_ENCODING, 17):
            flags |= _RF_TRANSFER_ENCODING
            if value is not None:
                flags &= ~_RF_TRANSFER_CHUNKED
                if _endswith_lc(value, len(value), _CHUNKED, 7):
                    flags |= _RF_TRANSFER_CHUNKED

        self._length = length
        self._flags = flags

    def endheaders(self, message_body=None, *, encode_chunked=None):
        if self._state != _CS_REQUEST_BUILDING:
            raise CannotSendHeader()

        try:
            message_body = self._prep_request(message_body, encode_chunked)
        except Exception:
            self._reset_request()
            raise

        try:
            if self._sock is None:
                self._open_socket()
            self._send_bytes(self._head, False)
            if _RECYCLE_BUFFERS and len(self._head) <= _REQUEST_HEAD_SIZE:
                self._head[:] = b""
            else:
                self._head = None
            self._count = 0
            self._state = _CS_REQUEST_HEAD_OPEN
            self._send_body(message_body)
        except Exception:
            self._abort_request()
            raise

    def send(self, body):
        if self._state != _CS_REQUEST_HEAD_OPEN and self._state != _CS_REQUEST_BODY_OPEN:
            raise CannotSendRequest()
        if self._sock is None:
            raise NotConnected()

        old_bytes = self._count
        try:
            self._send_body(body)
        except Exception:
            self._abort_request()
            raise
        return self._count - old_bytes

    def getresponse(self, *, all_headers=None, and_cookies=None):
        state = self._state
        if self._resp is not None or (
            state != _CS_REQUEST_HEAD_OPEN
            and state != _CS_REQUEST_BODY_OPEN
            and state != _CS_RESPONSE_ACTIVE
        ):
            raise ResponseNotReady()
        if self._sock is None:
            raise NotConnected()

        resp = None
        try:
            if state == _CS_REQUEST_HEAD_OPEN:
                if not (self._flags & (_RF_CONTENT_LENGTH | _RF_TRANSFER_ENCODING)):
                    if self.method in (b"PATCH", b"POST", b"PUT"):
                        if self._count == 0:
                            self._send_bytes(b"Content-Length: 0\r\n", False)
                            self._flags |= _RF_CONTENT_LENGTH
                            self._length = 0
                self._send_bytes(b"\r\n", False)
                state = self._state = _CS_REQUEST_BODY_OPEN
            if state == _CS_REQUEST_BODY_OPEN:
                self._state = _CS_RESPONSE_ACTIVE
                if self._chunked:
                    self._send_bytes(b"0\r\n\r\n", False)
                if self._length is not None and self._count != self._length:
                    raise RequestLengthMismatch(self._count, self._length)

            if _GC_FREE_THRESHOLD and gc.mem_free() < _GC_FREE_THRESHOLD:
                gc.collect()

            status = None
            try:
                while True:
                    version, status, reason = _parse_status_line(self._sock)
                    headers = _parse_headers(
                        self._sock, status, all_headers, and_cookies)
                    if status != 100:
                        break
            except OSError as e:
                raise IncompleteRead(_errno(e.errno), "socket read failed", None, None, status)

            response_chunked, response_length, reusable = _derive_response_framing(
                self.method, version, status, headers)

            if status < 200 and status != 101:
                sock = owner = None
                if not reusable:
                    self._flags |= _RF_CONNECTION_CLOSE
            else:
                sock = self._sock
                reusable = reusable and not (self._flags & _RF_CONNECTION_CLOSE)
                owner = self

            self._state = _CS_RESPONSE_CREATING

            resp = self.response_class(
                owner, sock, self.method, self.url, version, status, reason,
                headers, response_chunked, response_length)

            if self._state != _CS_RESPONSE_CREATING:
                raise ResponseNotReady()

            if sock is None:
                self._state = _CS_RESPONSE_ACTIVE
                return resp

            self._sock = None
            self._resp = resp
            self._state = _CS_RESPONSE_REUSABLE if reusable else _CS_RESPONSE_ACTIVE

            if response_length == 0 and status != 101:
                resp.close()

            return resp
        except Exception:
            self._abort_request(resp)
            raise

    def _open_socket(self):
        state = self._state
        try:
            network = self._network
            if network is not None:
                try:
                    network = network()
                except (MemoryError, OSError):
                    raise
                except Exception as e:
                    raise OSError(ENETDOWN, str(e))
                if self._state != state or self._sock is not None:
                    raise CannotSendRequest()
                if not network:
                    raise OSError(ENETUNREACH, "network unreachable")

            if _GC_FREE_THRESHOLD and gc.mem_free() < _GC_FREE_THRESHOLD:
                gc.collect()
            self._sock = create_connection((self.host, self.port), self.timeout)
        except OSError as e:
            raise ConnectError(_errno(e.errno), str(e))

    def _prep_request(self, body, encode_chunked):
        if isinstance(body, str):
            body = body.encode()

        flags = self._flags
        length = self._length

        if encode_chunked is not None:
            encode_chunked = bool(encode_chunked)
        elif flags & _RF_TRANSFER_ENCODING:
            encode_chunked = bool(flags & _RF_TRANSFER_CHUNKED)
        elif flags & _RF_CONTENT_LENGTH:
            encode_chunked = False
        elif isinstance(body, _BUFFER_TYPES):
            encode_chunked = False
            length = len(body)
        else:
            encode_chunked = (body is not None)

        self._chunked = encode_chunked

        if not (flags & _RF_TRANSFER_ENCODING):
            if encode_chunked:
                self._append_header(_TRANSFER_ENCODING, _CHUNKED)
                flags |= _RF_TRANSFER_ENCODING | _RF_TRANSFER_CHUNKED
            elif not (flags & _RF_CONTENT_LENGTH):
                if length is not None and length >= 0:
                    self._append_header(_CONTENT_LENGTH, b"%d" % length)
                    flags |= _RF_CONTENT_LENGTH

        if not (flags & _RF_HOST):
            if self.method == b"CONNECT":
                self._append_header(_HOST, self.url)
            else:
                hostport = _parse_hostport_from_url(self.url)
                if hostport:
                    self._append_header(_HOST, hostport)
                elif hostport is None:
                    self._append_header(_HOST, self._hostport)
                else:
                    raise InvalidURL(self.url)

        if not (flags & _RF_ACCEPT_ENCODING):
            self._append_header(_ACCEPT_ENCODING, b"identity")

        if length == -1:
            length = None
        self._length = length
        self._flags = flags
        return body

    def _append_header(self, name, value):
        self._head.extend(name)
        self._head.extend(b": ")
        self._head.extend(value)
        self._head.extend(b"\r\n")

    def _send_body(self, body):
        send = self._send_chunk if self._chunked else self._send_bytes

        if callable(body):
            body = body()

        if isinstance(body, str):
            body = body.encode()

        if body is None:
            return

        if self._state == _CS_REQUEST_HEAD_OPEN:
            self._send_bytes(b"\r\n", False)
            self._state = _CS_REQUEST_BODY_OPEN

        if isinstance(body, _BUFFER_TYPES):
            send(body)
            return

        reader = getattr(body, "readinto", None)
        if callable(reader):
            if self._length is None:
                size = _READ_BLOCK_SIZE
            else:
                size = max(_READ_BLOCK_SIZE >> 3, min(_READ_BLOCK_SIZE, self._length - self._count))
            buf = bytearray(size)
            bmv = memoryview(buf)
            while True:
                n = reader(buf)
                if type(n) is not int or n < 0 or n > size:
                    raise TypeError("invalid body part")
                if not n:
                    return
                send(bmv if n == size else bmv[:n])

        reader = getattr(body, "read", None)
        if callable(reader):
            while True:
                buf = reader(_READ_BLOCK_SIZE)
                if isinstance(buf, str):
                    buf = buf.encode()
                if not isinstance(buf, _BUFFER_TYPES):
                    raise TypeError("invalid body part")
                if not buf:
                    return
                send(buf)
                buf = None

        for buf in body:
            if isinstance(buf, str):
                buf = buf.encode()
            if not isinstance(buf, _BUFFER_TYPES):
                raise TypeError("invalid body part")
            send(buf)
            buf = None

    def _send_chunk(self, data):
        if not data:
            return
        len_data = len(data)
        self._send_bytes(
            _READ_BLOCK_SIZE_HEXCRLF if len_data == _READ_BLOCK_SIZE
            else b"%X\r\n" % len_data, False)
        self._send_bytes(data)
        self._send_bytes(b"\r\n", False)

    def _send_bytes(self, data, accounting=True):
        if self._sock is None:
            raise NotConnected()
        if not data:
            return

        try:
            self._sock.sendall(data)
        except OSError as e:
            raise IncompleteWrite(_errno(e.errno), "socket write failed", self._count, self._length)

        if accounting:
            self._count += len(data)

    def _release_response(self, response, sock, complete):
        reusable = complete and self._state == _CS_RESPONSE_REUSABLE and self._resp is response
        if self._resp is response:
            self._sock = sock if reusable else None
            self._reset_request()
        if complete is not None and not reusable:
            _close_quietly(sock)

    def _reset_request(self):
        self._state = _CS_IDLE
        self._resp = None
        self.method = None
        self.url = None
        self._length = None
        self._count = None
        self._flags = 0
        self._chunked = False

        if (
            _RECYCLE_BUFFERS
            and self._head is not None
            and len(self._head) <= _REQUEST_HEAD_SIZE
        ):
            self._head[:] = b""
        else:
            self._head = None

    def _abort_request(self, resp=None):
        if resp is None:
            resp = self._resp

        sock, self._sock = self._sock, None
        resp_sock = None
        try:
            if resp is not None and not resp.closed:
                resp_sock = resp.detach()
        finally:
            self._reset_request()
            if resp_sock is not sock:
                _close_quietly(resp_sock)
            _close_quietly(sock)

if _SSL_ENABLED:

    import ssl

    class HTTPSConnection(HTTPConnection):
        default_port = HTTPS_PORT

        def __init__(self, host, port=None, *,
                     timeout=_DEFAULT_TIMEOUT, network=None, context=None):
            super().__init__(host, port, timeout=timeout, network=network)
            if context is None:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.verify_mode = ssl.CERT_NONE
            self._context = context

        def _open_socket(self):
            super()._open_socket()
            raw, self._sock = self._sock, None
            gc.collect()
            try:
                if self._hostname:
                    self._sock = self._context.wrap_socket(raw, server_hostname=self._hostname)
                else:
                    self._sock = self._context.wrap_socket(raw)
                raw = None
            except MemoryError:
                _close_quietly(raw)
                raw = None
                raise
            except Exception as e:
                _close_quietly(raw)
                raw = None
                if isinstance(e, OSError):
                    raise ConnectError(_errno(e.errno), str(e))
                raise ConnectError(ENONET, str(e))
            finally:
                gc.collect()
