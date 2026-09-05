# client_ish.py
#
# Serious HTTP for tiny devices.

import micropython, socket, gc

## esp32 (because MICROPY_USE_INTERNAL_ERRNO == 0)
ENONET = const(64)
ENETDOWN = const(115)
ENETUNREACH = const(114)
EHOSTDOWN = const(117)
EHOSTUNREACH = const(118)
## otherwise (we use the same values as linux uapi)
#ENONET = const(64)
#ENETDOWN = const(100)
#ENETUNREACH = const(101)
#EHOSTDOWN = const(112)
#EHOSTUNREACH = const(113)

_COMPATISH_EXCEPTIONS = const(0)
_COMPATISH_MOST_METHODS = const(0)
_COMPATISH_DECODE_HEADERS = const(0)
_COMPATISH_REAL_REASON = const(0)

_EXTRA_METHODS = const(1)
_READ_CAN_RETURN_BYTEARRAY = const(1)
_RECYCLE_BUFFERS = const(1)
_SSL_ENABLED = const(1)

_DEFAULT_WITH_HEADERS = const(0) # i.e. False
_DEFAULT_TIMEOUT = const(10)
_GC_FREE_THRESHOLD = const(32768)
_READ_BLOCK_SIZE = const(1024)
_READ_BLOCK_SIZE_HEXCRLF = const(b"400\r\n")
_REQUEST_HEAD_SIZE = const(256)

_RF_HOST = const(1)
_RF_CONNECTION_CLOSE = const(4)
_RF_CONTENT_LENGTH = const(8)
_RF_ACCEPT_ENCODING = const(16)
_RF_TRANSFER_ENCODING = const(32)
_RF_TRANSFER_CHUNKED = const(64)

_CM_UNKNOWN = const(0)
_CM_CLOSE = const(1)
_CM_KEEPALIVE = const(2)

_CS_IDLE = const(0)
_CS_REQUEST_BUILDING = const(1)
_CS_REQUEST_HEAD_OPEN = const(2)
_CS_REQUEST_BODY_OPEN = const(3)
_CS_RESPONSE_CREATING = const(4)
_CS_RESPONSE_ACTIVE = const(5)
_CS_RESPONSE_REUSABLE = const(6)

_ACCEPT_ENCODING = const(b"Accept-Encoding")
_CONNECTION = const(b"Connection")
_CONTENT_LENGTH = const(b"Content-Length")
_HOST = const(b"Host")
_LOCATION = const(b"Location")
_SET_COOKIE = const(b"Set-Cookie")
_TRANSFER_ENCODING = const(b"Transfer-Encoding")

_CHUNKED = const(b"chunked")
_OK = const(b"OK")
_NOT_OK = const(b"Not OK")

_BUFFER_TYPES = (bytes, bytearray, memoryview)

class HTTPException(Exception): pass

class ImproperConnectionState(HTTPException): pass
class CannotSendRequest(ImproperConnectionState): pass
class CannotSendHeader(ImproperConnectionState): pass
class ResponseNotReady(ImproperConnectionState): pass
class NotConnected(ImproperConnectionState): pass

class BadStatusLine(HTTPException):
    def __init__(self, line):
        if _COMPATISH_EXCEPTIONS:
            if isinstance(line, _BUFFER_TYPES):
                line = decode_latin1(line)
            if not line:
                line = repr(line)
        elif _COMPATISH_DECODE_HEADERS:
            if isinstance(line, _BUFFER_TYPES):
                line = decode_latin1(line)
        self.errno = None
        self.args = line,
        self.line = line

if _COMPATISH_EXCEPTIONS:
    class UnknownProtocol(HTTPException):
        def __init__(self, version):
            if isinstance(version, _BUFFER_TYPES):
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
def _startswith(haystack_ptr: ptr8, needle_ptr: ptr8, needle_len: int, ci_flag: bool) -> bool:
    i = 0
    while i < needle_len:
        x = haystack_ptr[i]
        y = needle_ptr[i]
        if x != y:
            if not ci_flag:
                return False
            x |= 32
            y |= 32
            if x != y or x < 97 or x > 122:
                return False
        i += 1
    return True

@micropython.viper
def _connection_mode(haystack: object, value_start: int, mode: int) -> int:
    if mode == _CM_CLOSE:
        return mode

    end = int(len(haystack))
    haystack_ptr = ptr8(haystack)
    i = value_start

    while i < end:
        # Skip whitespace and empty list members.
        while i < end:
            x = haystack_ptr[i]
            if x > 32 and x != 44:
                break
            i += 1
        if i == end:
            return mode

        x |= 32

        if x == 99:  # "close" ?
            if ((end - i >= 5)
                and (haystack_ptr[i + 1] | 32) == 108
                and (haystack_ptr[i + 2] | 32) == 111
                and (haystack_ptr[i + 3] | 32) == 115
                and (haystack_ptr[i + 4] | 32) == 101
            ):
                j = i + 5
                while j < end and haystack_ptr[j] <= 32:
                    j += 1
                if j == end:
                    return _CM_CLOSE
                if haystack_ptr[j] == 44:
                    return _CM_CLOSE

        elif x == 107:  # "keep-alive" ?
            if ((end - i >= 10)
                and (haystack_ptr[i + 1] | 32) == 101
                and (haystack_ptr[i + 2] | 32) == 101
                and (haystack_ptr[i + 3] | 32) == 112
                and (haystack_ptr[i + 4]     ) == 45
                and (haystack_ptr[i + 5] | 32) == 97
                and (haystack_ptr[i + 6] | 32) == 108
                and (haystack_ptr[i + 7] | 32) == 105
                and (haystack_ptr[i + 8] | 32) == 118
                and (haystack_ptr[i + 9] | 32) == 101
            ):
                j = i + 10
                while j < end and haystack_ptr[j] <= 32:
                    j += 1
                if j == end:
                    return _CM_KEEPALIVE
                if haystack_ptr[j] == 44:
                    mode = _CM_KEEPALIVE
                    i = j + 1
                    continue

        # Skip an unrecognized or malformed member.
        while i < end and haystack_ptr[i] != 44:
            i += 1

        i += 1

    return mode

@micropython.viper
def _encoding_chunked(haystack: object, value_start: int, mode: bool) -> bool:
    end = int(len(haystack))
    haystack_ptr = ptr8(haystack)

    # Remove trailing whitespace and empty members.
    while end > value_start and (haystack_ptr[end - 1] <= 32 or haystack_ptr[end - 1] == 44):
        end -= 1

    # This field line contains no nonempty member.
    if end == value_start:
        return mode

    if ((end - value_start < 7)
        or (haystack_ptr[end - 7] | 32) != 99
        or (haystack_ptr[end - 6] | 32) != 104
        or (haystack_ptr[end - 5] | 32) != 117
        or (haystack_ptr[end - 4] | 32) != 110
        or (haystack_ptr[end - 3] | 32) != 107
        or (haystack_ptr[end - 2] | 32) != 101
        or (haystack_ptr[end - 1] | 32) != 100
    ):
        return False

    end -= 7

    # Skip whitespace preceding "chunked".
    while end > value_start and haystack_ptr[end - 1] <= 32:
        end -= 1

    if end == value_start or haystack_ptr[end - 1] == 44:
        return True

    return False

@micropython.viper
def _slice_uint(buf_ptr: ptr8, start: int, end: int, base: int) -> int:
    while start < end and buf_ptr[start] <= 32:
        start += 1
    while end > start and buf_ptr[end - 1] <= 32:
        end -= 1
    if start == end:
        return -1

    if base == 16:
        cutoff = 0x03FFFFFF
        cutlim = 15
    else:
        cutoff = 0x06666666
        cutlim = 3

    value = 0
    while start < end:
        char = buf_ptr[start]
        if 48 <= char and char <= 57:
            digit = char - 48
        elif base == 16 and 65 <= char and char <= 70:
            digit = char - 55
        elif base == 16 and 97 <= char and char <= 102:
            digit = char - 87
        else:
            return -1
        if value > cutoff or (value == cutoff and digit > cutlim):
            return -1
        value = value * base + digit
        start += 1
    return value

@micropython.viper
def _validate(haystack: ptr8, haystack_len: int, strict: bool) -> bool:
    i = 0
    if strict:
        while i < haystack_len:
            if haystack[i] <= 32:
                return False
            i += 1
    else:
        while i < haystack_len:
            x = haystack[i]
            if x == 10 or x == 13:
                return False
            i += 1
    return True

def _encode_and_validate(x, strict):
    if x is None:
        return None
    if isinstance(x, str):
        x = x.encode()
    elif type(x) is int:
        x = b"%d" % x
    elif isinstance(x, memoryview):
        x = bytes(x)
    elif not isinstance(x, _BUFFER_TYPES):
        x = str(x).encode()
    if not _validate(x, len(x), strict):
        return None
    if not strict or type(x) is bytes:
        return x
    return bytes(x)

if _COMPATISH_DECODE_HEADERS or _COMPATISH_EXCEPTIONS:

    @micropython.viper
    def _latin1_to_utf8(src: ptr8, end: int, dst: ptr8) -> int:
        write = int(dst) != 0
        dstlen = 0
        i = 0
        while i < end:
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
        if utf8len == buflen and not isinstance(buf, memoryview):
            return buf.decode()
        utf8out = bytearray(utf8len)
        _latin1_to_utf8(buf, buflen, utf8out)
        return utf8out.decode()

if _COMPATISH_DECODE_HEADERS:

    def _decode_latin1_pair(a, b):
        return (decode_latin1(a), decode_latin1(b))

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
    end = len(url)
    if end >= 7 and _startswith(url, b"http://", 7, True):
        start = 7
    elif end >= 8 and _startswith(url, b"https://", 8, True):
        start = 8
    else:
        return None
    pos = url.find(b"/", start)
    if pos >= 0:
        end = pos
    pos = url.find(b"?", start, end)
    if pos >= 0:
        end = pos
    pos = url.find(b"#", start, end)
    if pos >= 0:
        end = pos
    pos = url.rfind(b"@", start, end)
    if pos >= 0:
        start = pos + 1
    return memoryview(url)[start:end]

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
        line_length = len(line)

        if line_length < 4 or line[line_length - 1] != 10:
            break

        pos = 4
        while pos < line_length and line[pos] > 32:
            pos += 1
        if pos == line_length:
            break

        if pos == 7 and _startswith(line, b"TTP/1.0", 7, False):
            first = 10
        elif pos >= 6 and _startswith(line, b"TTP/1.", 6, False):
            first = 11
        elif not _startswith(line, b"TTP/", 4, False):
            break
        elif _COMPATISH_EXCEPTIONS:
            raise UnknownProtocol(b"H" + line[:pos])
        else:
            raise UnknownProtocol(b"H" + line)

        while pos < line_length and line[pos] <= 32:
            pos += 1
        if pos + 3 >= line_length or line[pos + 3] > 32:
            break
        status = _slice_uint(line, pos, pos + 3, 10)
        if status < 100:
            break

        if _COMPATISH_REAL_REASON:
            pos += 3
            while pos < line_length and line[pos] <= 32:
                pos += 1
            while line_length > pos and line[line_length-1] <= 32:
                line_length -= 1
            return (first, status, b"" if pos == line_length else line[pos:line_length])
        else:
            return (first, status, _OK if (status == 200) else _NOT_OK)

    raise BadStatusLine(b"H" + line)

def _header_value(line, name_length):
    name_length += 1
    value_end = len(line)
    while name_length < value_end and line[name_length] <= 32:
        name_length += 1
    while value_end > name_length and line[value_end - 1] <= 32:
        value_end -= 1
    return line[name_length:value_end]

def _parse_headers(sock, status, with_headers):
    headers = None
    content_length = None
    content_chunked = None
    new_location = None
    connection = _CM_UNKNOWN

    while True:
        line = sock.readline()
        if not line:
            raise IncompleteRead(None, "EOF in response headers", None, None, status)
        if line[-1] != 10:
            raise IncompleteRead(None, "unterminated response header", None, None, status)
        if line == b"\r\n" or line == b"\n":
            if headers is None:
                headers = ()
            return headers, connection, content_chunked, content_length, new_location
        if line[0] <= 32:
            continue

        name_length = line.find(b":")
        if name_length == -1:
            continue

        retained_name = None
        if with_headers is True:
            retained_name = line[:name_length]
        elif with_headers:
            for retained_name in with_headers:
                if len(retained_name) == name_length and _startswith(line, retained_name, name_length, True):
                    break
            else:
                retained_name = None

        if name_length == 8 and _startswith(line, _LOCATION, 8, True):
            line = _header_value(line, name_length)
            new_location = line

        elif name_length == 10 and _startswith(line, _CONNECTION, 10, True):
            connection = _connection_mode(line, 11, connection)
            if retained_name is not None:
                line = _header_value(line, 10)

        elif name_length == 14 and _startswith(line, _CONTENT_LENGTH, 14, True):
            name_length = _slice_uint(line, 15, len(line), 10)

            if content_length is None:
                content_length = name_length
            elif content_length >= 0 and content_length != name_length:
                content_length = -1

            if retained_name is not None:
                line = _header_value(line, 14)

        elif name_length == 17 and _startswith(line, _TRANSFER_ENCODING, 17, True):
            content_chunked = _encoding_chunked(line, 18, content_chunked is True)

            if retained_name is not None:
                line = _header_value(line, 17)

        elif retained_name is not None:
            line = _header_value(line, name_length)

        else:
            continue

        if retained_name is not None:
            if headers is None:
                headers = []
            headers.append((retained_name, line))

class HTTPResponse:
    _chunk_left = None

    def __init__(self, owner, sock, method, url, version, status, reason, headers, chunked, length, location):
        self._owner = owner
        self._sock = sock
        self.method = method # bytes
        if _COMPATISH_DECODE_HEADERS:
            self._url = url
        else:
            self.url = url
        self.version = version # int
        self.status = status
        if _COMPATISH_MOST_METHODS:
            self.code = status
        if _COMPATISH_DECODE_HEADERS:
            self._reason = reason
        else:
            self.reason = reason
        self._headers = headers
        self._chunked = chunked
        self._length = length
        if _COMPATISH_DECODE_HEADERS:
            self._location = location
        else:
            self.location = location
        self._count = 0

    if _COMPATISH_DECODE_HEADERS:
        @property
        def url(self):
            return decode_latin1(self._url)

        @property
        def reason(self):
            return decode_latin1(self._reason)

        @property
        def location(self):
            return decode_latin1(self._location)

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
        owner._release_response(self, None, False)
        return sock

    if _EXTRA_METHODS:

        def detach_async(self):
            import asyncio
            sock = self.detach()
            try:
                sock.setblocking(False)
                return asyncio.Stream(sock)
            except Exception:
                _close_quietly(sock)
                raise

    def items(self):
        if _COMPATISH_DECODE_HEADERS:
            return (_decode_latin1_pair(key, val) for key, val in self._headers)
        else:
            return iter(self._headers)

    def getheaders(self):
        if _COMPATISH_DECODE_HEADERS:
            return [_decode_latin1_pair(key, val) for key, val in self._headers]
        else:
            return list(self._headers)

    def getheadervalues(self, name):
        name = _encode_and_validate(name, False)
        result = []
        if name is not None:
            name_length = len(name)
            for key, val in self._headers:
                if len(key) == name_length and _startswith(key, name, name_length, True):
                    if _COMPATISH_DECODE_HEADERS:
                        result.append(decode_latin1(val))
                    else:
                        result.append(val)
        return result

    def getheader(self, name, default=None):
        values = self.getheadervalues(name)
        if not values:
            return default
        elif len(values) == 1:
            return values[0]
        elif _COMPATISH_DECODE_HEADERS:
            return ", ".join(values)
        else:
            return b", ".join(values)

    if _EXTRA_METHODS:

        def _itercookies(self, name, raw):
            if name is not None:
                name = _encode_and_validate(name, False)
                if name is None:
                    return
                name_length = len(name)

            for key, val in self._headers:
                if len(key) != 10 or not _startswith(key, _SET_COOKIE, 10, True):
                    continue

                pos = val.find(b"=")
                if pos <= 0:
                    continue

                if name is not None:
                    if pos != name_length or not _startswith(val, name, pos, False):
                        continue
                else:
                    key = val[:pos]

                if not raw:
                    pos += 1
                    end = val.find(b";", pos)
                    if end < 0:
                        end = len(val)
                    val = val[pos:end]

                if _COMPATISH_DECODE_HEADERS:
                    if name is None:
                        yield _decode_latin1_pair(key, val)
                    else:
                        yield decode_latin1(val)
                else:
                    if name is None:
                        yield key, val
                    else:
                        yield val

        def getcookies(self):
            return list(self._itercookies(None, False))

        def getrawcookies(self):
            return list(self._itercookies(None, True))

        def getcookie(self, name, default=None):
            result = default
            for val in self._itercookies(name, False):
                result = val # last match wins
            return result

        def getrawcookie(self, name, default=None):
            result = default
            for val in self._itercookies(name, True):
                result = val # last match wins
            return result

        def drain(self, buf=None):
            if buf is None:
                size = _READ_BLOCK_SIZE
                if self._length is not None:
                    size = min(size, self._length - self._count)
                if size == 0:
                    return
                buf = bytearray(size)
            elif not buf:
                raise ValueError("empty buffer")
            while self.readinto(buf):
                pass

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
                if _COMPATISH_EXCEPTIONS:
                    return 0 if into else b""
                else:
                    if self._length is not None and self._count >= self._length:
                        return 0 if into else b""
                    raise NotConnected()

            if into:
                if not buf:
                    return 0
                amt = len(buf)
            elif amt is not None and amt < 0:
                amt = None

            if _COMPATISH_EXCEPTIONS:
                bounded = amt is not None

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
                    if _COMPATISH_EXCEPTIONS:
                        self.close()
                        return 0
                    else:
                        self._abort_read("EOF in response body")

                self._count += n
                if self._length is not None and self._count >= self._length:
                    self.close()
                return n

            out = buf if into else (b"" if amt is None else bytearray(amt))
            total = 0
            data = None

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
                elif not total:
                    n = sock.readinto(out, n)
                else:
                    if data is None:
                        data = out if isinstance(out, memoryview) else memoryview(out)
                    n = sock.readinto(data[total:], n)

                if not n:
                    if self._chunked:
                        self._abort_read("EOF in chunk data")
                    if self._length is not None:
                        if not (_COMPATISH_EXCEPTIONS and bounded):
                            self._abort_read("EOF in response body")
                        self.close()
                        break
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

            if not _READ_CAN_RETURN_BYTEARRAY and type(out) is not bytes:
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
            if _COMPATISH_EXCEPTIONS:
                self._release_socket(False)
                raise
            else:
                self._abort_read("socket read failed", e.errno)

    def _get_chunk_left(self):
        while True:
            if self._chunk_left is None:
                line = self._sock.readline()
                if not line:
                    self._abort_read("EOF before chunk size")
                line_length = len(line)
                if (line_length < 2 or line[line_length - 2] != 13 or line[line_length - 1] != 10):
                    self._abort_read("invalid chunk-size line ending")
                size_end = line.find(b";")
                if size_end < 0:
                    size_end = line_length - 2
                size = _slice_uint(line, 0, size_end, 16)
                if size < 0:
                    self._abort_read("invalid chunk size")
                if size > 0:
                    self._chunk_left = size
                    return size
                while True:
                    line = self._sock.readline()
                    if not line:
                        self._abort_read("EOF in chunk trailers")
                    line_length = len(line)
                    if (line_length < 2 or line[line_length - 2] != 13 or line[line_length - 1] != 10):
                        self._abort_read("invalid chunk trailer line ending")
                    if line_length == 2:  # exactly b"\r\n"
                        self._length = self._count
                        self.close()
                        return 0
            elif self._chunk_left == 0:
                if self._sock.read(2) != b"\r\n":
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

        def get_all(self, name, default=None):
            name = _encode_and_validate(name, False)
            if name is None:
                return default
            length = len(name)
            values = None
            for key, val in self._headers:
                if len(key) == length and _startswith(key, name, length, True):
                    if values is None:
                        values = []
                    if _COMPATISH_DECODE_HEADERS:
                        values.append(decode_latin1(val))
                    else:
                        values.append(val)
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
    default_port = 80
    timeout = _DEFAULT_TIMEOUT
    _network = None

    def __init__(self, host, port=None, timeout=None, *, network=None):
        the_host = _encode_and_validate(host, True)
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
                    port = _slice_uint(the_host, sep + 2, len(the_host), 10)
                the_host = the_host[:sep + 1]
            hostaddr = the_host[1:sep]
        elif colons == 1:
            sep = the_host.find(b":")
            if sep + 1 < len(the_host):
                if port is None:
                    port = _slice_uint(the_host, sep + 1, len(the_host), 10)
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
            if _COMPATISH_EXCEPTIONS:
                raise InvalidURL("port invalid")
            else:
                raise TypeError("port invalid")

        self.host = hostaddr
        self._hostname = hostname
        if port == self.default_port:
            self._hostport = the_host
        else:
            self._hostport = b"%s:%d" % (the_host, port)
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
                for key, val in headers:
                    self.putheader(key, val)
        except Exception:
            self._reset_request()
            raise

        self.endheaders(body, encode_chunked=encode_chunked)

    def putrequest(self, method, url, skip_host=False, skip_accept_encoding=False):
        if self._state != _CS_IDLE:
            raise CannotSendRequest()

        method = _encode_and_validate(method, True)
        if not method:
            raise ValueError("invalid method")
        if not method.isupper():
            method = method.upper()

        if url:
            valid_url = _encode_and_validate(url, True)
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

        name = _encode_and_validate(name, False)
        if name is None:
            raise ValueError("invalid header name")
        if value is not None:
            value = _encode_and_validate(value, False)
            if value is None:
                raise ValueError("invalid header value")
            try:
                self._append_header(name, value)
            except MemoryError:
                self._head = None
                self._reset_request()
                gc.collect()
                raise

        name_length = len(name)
        length = self._length
        flags = self._flags

        if name_length == 4 and _startswith(name, _HOST, 4, True):
            flags |= _RF_HOST
        elif name_length == 10 and _startswith(name, _CONNECTION, 10, True):
            if value is not None and _connection_mode(value, 0, _CM_UNKNOWN) == _CM_CLOSE:
                flags |= _RF_CONNECTION_CLOSE
        elif name_length == 14 and _startswith(name, _CONTENT_LENGTH, 14, True):
            flags |= _RF_CONTENT_LENGTH
            if value is not None:
                value = _slice_uint(value, 0, len(value), 10)
                if value >= 0 and (length is None or length == value):
                    length = value
                else:
                    length = -1
        elif name_length == 15 and _startswith(name, _ACCEPT_ENCODING, 15, True):
            flags |= _RF_ACCEPT_ENCODING
        elif name_length == 17 and _startswith(name, _TRANSFER_ENCODING, 17, True):
            flags |= _RF_TRANSFER_ENCODING
            if value is not None:
                if _encoding_chunked(value, 0, bool(flags & _RF_TRANSFER_CHUNKED)):
                    flags |= _RF_TRANSFER_CHUNKED
                else:
                    flags &= ~_RF_TRANSFER_CHUNKED

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

        old_bytes = self._count
        try:
            self._send_body(body)
        except Exception:
            self._abort_request()
            raise
        return self._count - old_bytes

    def getresponse(self, *, with_headers=None):
        state = self._state
        if (state != _CS_REQUEST_HEAD_OPEN and state != _CS_REQUEST_BODY_OPEN):
            raise ResponseNotReady()

        method = self.method
        sock = self._sock
        resp = None
        try:
            if state == _CS_REQUEST_HEAD_OPEN:
                if not (self._flags & (_RF_CONTENT_LENGTH | _RF_TRANSFER_ENCODING)):
                    if method in (b"PATCH", b"POST", b"PUT"):
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

            if with_headers is None:
                if not _DEFAULT_WITH_HEADERS:
                    with_headers = False
                elif type(_DEFAULT_WITH_HEADERS) is int:
                    with_headers = True
                else:
                    with_headers = _DEFAULT_WITH_HEADERS

            if not with_headers or isinstance(with_headers, bool):
                pass
            elif type(with_headers) is bytes:
                with_headers = (with_headers, )
            elif isinstance(with_headers, _BUFFER_TYPES):
                with_headers = (bytes(with_headers), )
            elif isinstance(with_headers, str):
                with_headers = (with_headers.encode(), )
            elif type(with_headers) is not frozenset:
                with_headers = [
                    name if type(name) is bytes
                    else bytes(name) if isinstance(name, _BUFFER_TYPES)
                    else name.encode() if isinstance(name, str)
                    else name
                    for name in with_headers
                ]

            status = None
            try:
                while True:
                    version, status, reason = _parse_status_line(sock)
                    if 100 <= status < 200 and status != 101:
                        _parse_headers(sock, status, False)
                        continue
                    headers, connection, chunked, content_length, new_location = _parse_headers(
                        sock, status, with_headers)
                    break
            except OSError as e:
                if _COMPATISH_EXCEPTIONS:
                    raise
                else:
                    raise IncompleteRead(e.errno, "socket read failed", None, None, status)

            reusable = version != 10

            if connection == _CM_CLOSE:
                reusable = False
            elif connection == _CM_KEEPALIVE:
                reusable = True

            if chunked and (version == 10 or content_length is not None):
                reusable = False

            if status == 101:
                reusable = False
                content_length = 0
                chunked = False
            elif 200 <= status < 300 and method == b"CONNECT":
                reusable = False
                content_length = None
                chunked = False
            elif status == 204:
                reusable = (
                    reusable and chunked is None
                    and (content_length is None or content_length == 0))
                content_length = 0
                chunked = False
            elif status == 304 or method == b"HEAD":
                reusable = reusable and content_length != -1
                content_length = 0
                chunked = False
            elif chunked is True:
                content_length = None
            elif chunked is False:
                reusable = False
                if content_length is None or content_length < 0:
                    content_length = None
            elif content_length == -1:
                reusable = False
                content_length = None
            else:
                reusable = reusable and content_length is not None

            reusable = reusable and not (self._flags & _RF_CONNECTION_CLOSE)

            self._state = _CS_RESPONSE_CREATING

            resp = self.response_class(
                self, sock, method, self.url, version, status, reason,
                headers, chunked is True, content_length, new_location)

            if self._state != _CS_RESPONSE_CREATING or resp.closed:
                raise ResponseNotReady()

            self._sock = None
            self._resp = resp
            self._state = _CS_RESPONSE_REUSABLE if reusable else _CS_RESPONSE_ACTIVE

            if content_length == 0 and status != 101:
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
            if _COMPATISH_EXCEPTIONS:
                raise
            else:
                raise ConnectError(e.errno, str(e))

    def _prep_request(self, body, encode_chunked):
        if isinstance(body, str):
            body = body.encode()

        flags = self._flags
        length = self._length

        if encode_chunked is not None:
            encode_chunked = bool(encode_chunked)
            if (
                not encode_chunked
                and not (flags & (_RF_CONTENT_LENGTH | _RF_TRANSFER_ENCODING))
                and isinstance(body, _BUFFER_TYPES)
            ):
                length = len(body)
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
        head = self._head
        head.extend(name)
        head.extend(b": ")
        head.extend(value)
        head.extend(b"\r\n")

    def _send_body(self, body):
        send = (
            HTTPConnection._send_chunk
            if self._chunked else HTTPConnection._send_bytes
        )

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
            if body:
                send(self, body)
            return

        reader = getattr(body, "readinto", None)
        if reader is not None:
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
                send(self, bmv if n == size else bmv[:n])

        reader = getattr(body, "read", None)
        if reader is not None:
            while True:
                buf = reader(_READ_BLOCK_SIZE)
                if isinstance(buf, str):
                    buf = buf.encode()
                if not isinstance(buf, _BUFFER_TYPES):
                    raise TypeError("invalid body part")
                if not buf:
                    return
                send(self, buf)
                buf = None

        for buf in body:
            if isinstance(buf, str):
                buf = buf.encode()
            if not isinstance(buf, _BUFFER_TYPES):
                raise TypeError("invalid body part")
            if not buf:
                continue
            send(self, buf)
            buf = None

    def _send_chunk(self, data):
        data_length = len(data)
        self._send_bytes(
            _READ_BLOCK_SIZE_HEXCRLF if data_length == _READ_BLOCK_SIZE
            else b"%X\r\n" % data_length, False)
        self._send_bytes(data)
        self._send_bytes(b"\r\n", False)

    def _send_bytes(self, data, accounting=True):
        data_length = len(data)

        try:
            n = self._sock.write(data)
        except OSError as e:
            if _COMPATISH_EXCEPTIONS:
                raise
            else:
                raise IncompleteWrite(e.errno, "socket write failed", self._count, self._length)

        if type(n) is not int or n < 0 or n > data_length:
            raise IncompleteWrite(None, "invalid write", self._count, self._length)

        if accounting:
            self._count += n

        if n != data_length:
            raise IncompleteWrite(None, "short write", self._count, self._length)

    def _release_response(self, resp, sock, complete):
        if self._resp is not resp:
            _close_quietly(sock)
            return
        reusable = complete and self._state == _CS_RESPONSE_REUSABLE
        self._sock = sock if reusable else None
        self._reset_request()
        if not reusable:
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
        default_port = 443

        def __init__(self, host, port=None, *,
                     timeout=None, network=None, context=None):
            HTTPConnection.__init__(self, host, port, timeout=timeout, network=network)
            if context is None:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.verify_mode = ssl.CERT_NONE
            self._context = context

        def _open_socket(self):
            HTTPConnection._open_socket(self)
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
                if _COMPATISH_EXCEPTIONS:
                    raise
                elif isinstance(e, OSError):
                    raise ConnectError(e.errno, str(e))
                else:
                    raise ConnectError(ENONET, str(e))
            finally:
                gc.collect()
