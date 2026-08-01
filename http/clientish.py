# http/clientish.py
#
# Serious HTTP for tiny devices.

import micropython

_COMPATISH_EXCEPTIONS = const(0)
_DEFAULT_TIMEOUT = const(10)
_ENABLE_SSL = const(1)
_ENABLE_VIPER = const(1)
_GC_FREE_THRESHOLD = const(32768)
_READ_BLOCK_SIZE = const(2048)
_READ_MUST_RETURN_BYTES = const(0)
_RECYCLE_HEADER_BUFFER = const(1)
_REQUEST_HEAD_SIZE = const(512)

import socket, errno, gc
if _ENABLE_SSL:
    import ssl

HTTP_PORT = const(80)
HTTPS_PORT = const(443)
OK = const(200)

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
_CS_RESPONSE_ACTIVE = const(4)
_CS_RESPONSE_REUSABLE = const(5)

_ACCEPT_ENCODING = b"Accept-Encoding"
_CONNECTION = b"Connection"
_CONTENT_LENGTH = b"Content-Length"
_CONTENT_TYPE = b"Content-Type"
_HOST = b"Host"
_SET_COOKIE = b"Set-Cookie"
_TRANSFER_ENCODING = b"Transfer-Encoding"

_CHUNKED = b"chunked"
_CLOSE = b"close"

_BUFFER_TYPE = (bytes, bytearray, memoryview)

_KEEP_RESPONSE_HEADERS = (
    b"ETag",
    b"Location",
    _SET_COOKIE,
    _CONNECTION,
    b"Retry-After",
    _CONTENT_TYPE,
    _CONTENT_LENGTH,
    _TRANSFER_ENCODING,
)

_ENONET = getattr(errno, "ENONET", 64)
_ENETDOWN = getattr(errno, "ENETDOWN", 100)
_ENETUNREACH = getattr(errno, "ENETUNREACH", 101)
_EHOSTDOWN = getattr(errno, "EHOSTDOWN", 112)
_EHOSTUNREACH = getattr(errno, "EHOSTUNREACH", 113)

def _errno(err):
    return err or 0

class HTTPException(Exception): pass

class ImproperConnectionState(HTTPException): pass
class CannotSendRequest(ImproperConnectionState): pass
class CannotSendHeader(ImproperConnectionState): pass
class ResponseNotReady(ImproperConnectionState): pass
class NotConnected(ImproperConnectionState): pass

class BadStatusLine(HTTPException):
    def __init__(self, line):
        self.errno = None
        self.args = line,
        self.line = line

if _COMPATISH_EXCEPTIONS:
    class UnknownProtocol(HTTPException):
        def __init__(self, version):
            self.errno = None
            self.args = version,
            self.version = version
else:
    class UnknownProtocol(BadStatusLine): pass

class RequestLengthMismatch(HTTPException):
    def __init__(self, observed, expected):
        self.errno = None
        if _COMPATISH_EXCEPTIONS:
            self.partial = observed
            if type(observed) is int and type(expected) is int:
                self.expected = expected - observed
            else:
                self.expected = None
        else:
            self.observed = observed
            self.expected = expected
        self.args = (observed, self.expected)

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
                try: self.expected = _length - len(_count)
                except Exception: self.expected = None
            self.args = _count,
        else:
            self.count = _count
            self.length = _length
            self.args = (error, message)

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

def _encode_and_validate(x, strict=False):
    if x is None:
        return None
    if isinstance(x, str):
        x = x.encode()
    elif not isinstance(x, _BUFFER_TYPE):
        x = str(x).encode()
    if strict:
        for b in x:
            if b <= 32:
                return None
    else:
        for b in x:
            if b == 10 or b == 13:
                return None
    if not strict or type(x) is bytes:
        return x
    return bytes(x)

def _lower(x):
    if isinstance(x, memoryview):
        x = bytes(x)
    return (x if x.islower() else x.lower())

if _ENABLE_VIPER:
    @micropython.viper
    def _equals_ci(a:ptr8, b:ptr8, length:int) -> int:
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
else:
    def _equals_ci(a:ptr8, b:ptr8, length:int) -> int:
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

def _close_quietly(sock):
    if sock is not None:
        try:
            sock.close()
        except Exception:
            pass

def create_connection(address, timeout=None, *, resolver=None):
    host, port = address
    if resolver is None:
        resolver = socket.getaddrinfo
    try:
        infos = resolver(host, port, 0, socket.SOCK_STREAM)
    except OSError as e:
        raise OSError(_EHOSTDOWN, str(e))

    exc = None
    for f, t, p, _, a in infos:
        sock = None
        try:
            sock = socket.socket(f, t, p)
            if timeout != 0:
                sock.settimeout(timeout)
            try:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except (AttributeError, OSError):
                pass
            sock.connect(a)
            return sock
        except OSError as e:
            exc = e
            _close_quietly(sock)
        except Exception:
            _close_quietly(sock)
            raise
    if exc is None:
        raise OSError(_EHOSTUNREACH, "host unreachable")
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
        if not line.endswith(b"\n"):
            break
        if not line.startswith(b"TTP/"):
            break

        parts = line.split(None, 2)
        if len(parts) == 3:
            version, status, reason = parts
        elif len(parts) == 2:
            version, status = parts
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
    if and_cookies is None:
        and_cookies = all_headers

    headers = []
    while True:
        line = sock.readline()
        if not line:
            raise IncompleteRead(None, "connection closed while reading response headers", None, None, status)
        if not line.endswith(b"\n"):
            raise IncompleteRead(None, "incomplete response header line", None, None, status)
        if line == b"\r\n" or line == b"\n":
            return headers
        if line[0] <= 32:
            continue

        pos = line.find(b":")
        if pos == -1:
            continue

        name = None
        for cand in _KEEP_RESPONSE_HEADERS:
            if len(cand) == pos and _equals_ci(line, cand, pos):
                name = cand
                break

        if name is None:
            if not all_headers:
                continue
            name = line[:pos]
        elif name is _SET_COOKIE and not and_cookies:
            continue

        start, end = pos + 1, len(line)
        while start < end and line[start] <= 32: start += 1
        while end > start and line[end - 1] <= 32: end -= 1
        headers.append((name, line[start:end]))

def _derive_response_framing(method, version, status, response_headers):
    http10 = (version == 10)
    length = None
    chunked = None
    reusable = None

    for key, val in response_headers:
        if key is _CONTENT_LENGTH:
            val = int(val, 10) if val.isdigit() else -1
            if length is None:
                length = val
            elif length != val:
                length = -1

        elif key is _CONNECTION:
            if reusable is not False:
                len_val = len(val)
                if http10:
                    reusable = (len_val == 10 and _equals_ci(val, b"keep-alive", 10))
                elif len_val == 5:
                    reusable = not _equals_ci(val, _CLOSE, 5)
                elif len_val > 5:
                    reusable = _CLOSE not in _lower(val)

        elif key is _TRANSFER_ENCODING:
            len_val = len(val)
            if len_val == 7:
                chunked = bool(_equals_ci(val, _CHUNKED, 7))
            elif len_val > 7:
                chunked = _lower(val).endswith(_CHUNKED)
            else:
                chunked = False

    if reusable is None:
        reusable = not http10

    if chunked and (http10 or length is not None):
        reusable = False

    if status == 101:
        return False, 0, False

    if method == b"CONNECT" and 200 <= status < 300:
        return False, None, False

    if status < 200 or status == 204:
        return False, 0, (reusable and chunked is None and length is None)

    if method == b"HEAD" or status == 304:
        return False, 0, (reusable and length != -1)

    if chunked:
        return True, None, reusable

    if chunked is not None:
        if length is not None and length >= 0:
            return False, length, False
        return False, None, False

    if length == -1:
        return False, None, False

    return False, length, (reusable and length is not None)

class HTTPResponse:
    _chunk_left = None

    def __init__(self, owner, sock, method, url,
                 version, status, reason,
                 headers, chunked, length):
        if owner is None and sock is not None:
            raise ValueError("socket owner required")
        self._owner = owner
        self._sock = sock
        self.method = method
        self.url = url
        self.version = version
        self.status = status
        self.reason = reason.rstrip()
        self._headers = headers
        self._chunked = chunked
        self._length = length
        self._count = 0

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def getheaders(self):
        return self._headers

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
        return default if result is None else result

    @property
    def closed(self):
        return self._sock is None

    def read(self, amt=None):
        return self._read_body(None, amt)

    def readinto(self, buf):
        if buf is None:
            raise TypeError("buffer required")
        return self._read_body(buf, None)

    def drain(self, buf=None):
        if buf is None:
            buf = bytearray(_READ_BLOCK_SIZE)
        elif not buf:
            raise ValueError("non-empty buffer required")
        while self.readinto(buf):
            pass

    def detach(self):
        sock = self._sock
        if sock is None:
            raise NotConnected()
        owner = self._owner
        if owner is not None:
            owner._release_response(self, None, None)
        self._sock = self._owner = None
        return sock

    def close(self):
        self._release_socket(self._count == self._length)

    def _abort_read(self, message, error=None):
        self._release_socket(False)
        raise IncompleteRead(error, message, self._count, self._length, self.status)

    def _release_socket(self, complete):
        sock = self._sock
        owner = self._owner
        if owner is not None:
            owner._release_response(self, sock, complete)
        self._sock = self._owner = None

    def _get_chunk_left(self):
        while True:
            if self._chunk_left is None:
                line = self._sock.readline()
                if not line:
                    self._abort_read("unexpected EOF before chunk size")
                pos = line.find(b";")
                try:
                    if pos >= 0:
                        line = line[:pos]
                    size = int(line, 16)
                    if size < 0:
                        self._abort_read("negative chunk size")
                except ValueError:
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
                        self._abort_read("unexpected EOF in chunk trailers")
            elif self._chunk_left == 0:
                line = self._sock.readline()
                if not line:
                    self._abort_read("unexpected EOF before chunk terminator")
                if not (line == b"\r\n" or line == b"\n"):
                    self._abort_read("invalid chunk terminator")
                self._chunk_left = None
            else:
                return self._chunk_left

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
                remaining = self._length - self._count
                if remaining == 0:
                    self.close()
                    return 0 if into else b""
                if amt is None:
                    amt = remaining
                else:
                    amt = min(amt, remaining)

            if into and not self._chunked:
                n = sock.readinto(buf, amt)
                if not n:
                    if self._length is None:
                        self._length = self._count
                        self.close()
                        return 0
                    self._abort_read("unexpected EOF in response body")

                self._count += n
                if self._length is not None and self._count >= self._length:
                    self.close()
                return n

            out = buf if into else (b"" if amt is None else bytearray(amt))
            total = 0
            if amt is not None:
                bmv = out if isinstance(out, memoryview) else memoryview(out)

            while amt is None or total < amt:
                if into:
                    want = amt - total
                elif amt is None:
                    want = _READ_BLOCK_SIZE
                else:
                    want = min(amt - total, _READ_BLOCK_SIZE)

                if self._chunked:
                    want = min(want, self._get_chunk_left())
                    if want == 0:
                        break

                if amt is None:
                    data = sock.read(want)
                    n = len(data)
                else:
                    n = sock.readinto(bmv if not total else bmv[total:], want)

                if not n:
                    if self._chunked:
                        self._abort_read("unexpected EOF in chunk data")
                    if self._length is not None:
                        self._abort_read("unexpected EOF in response body")
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

            if into:
                return total

            if amt is not None and total < amt:
                out = out[:total]
            if _READ_MUST_RETURN_BYTES and type(out) is not bytes:
                out = bytes(out)
            return out
        except (MemoryError, OverflowError):
            out = bmv = data = None
            gc.collect()
            self._release_socket(False)
            raise
        except OSError as e:
            self._abort_read("socket read failed", _errno(e.errno))

class HTTPConnection:
    response_class = HTTPResponse
    default_port = HTTP_PORT

    def __init__(self, host, port=None, *, timeout=_DEFAULT_TIMEOUT, network=None):
        the_host = _encode_and_validate(host, True)
        if not the_host:
            raise InvalidURL(host)

        hostaddr = the_host
        hostname = None
        colons = the_host.count(b":")

        if the_host.startswith(b"["):
            if colons < 2 or not the_host.endswith(b"]"):
                raise InvalidURL(host)
            hostaddr = the_host[1:-1]
        elif colons == 1:
            raise InvalidURL(host)
        elif colons:
            the_host = b"[%s]" % the_host
        else:
            for b in the_host:
                if not (b == 46 or (48 <= b <= 57)):
                    hostname = the_host
                    break

        if port is None:
            port = self.default_port
        if not isinstance(port, int):
            raise TypeError("port must be an int")

        if port == self.default_port:
            hostport = the_host
        else:
            hostport = b"%s:%d" % (the_host, port)

        self.host = the_host
        self._hostaddr = hostaddr
        self._hostname = hostname
        self._hostport = hostport
        self.port = port

        self._timeout = timeout
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
        resp = self._resp
        if resp is not None:
            return resp.detach()
        sock, self._sock = self._sock, None
        self._reset_request()
        return sock

    def _release_response(self, response, sock, complete):
        reusable = (
            complete and
            self._state == _CS_RESPONSE_REUSABLE and
            self._resp is response)
        if self._resp is response:
            self._sock = sock if reusable else None
            self._reset_request()
        if complete is not None and not reusable:
            _close_quietly(sock)

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

    def putrequest(self, method, url, *, skip_host=False, skip_accept_encoding=False):
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
            gc.collect()
            self._reset_request()
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
            if value is not None:
                len_value = len(value)
                if len_value == 5:
                    if _equals_ci(value, _CLOSE, 5):
                        flags |= _RF_CONNECTION_CLOSE
                elif len_value > 5:
                    if _CLOSE in _lower(value):
                        flags |= _RF_CONNECTION_CLOSE
        elif len_name == 14 and _equals_ci(name, _CONTENT_LENGTH, 14):
            flags |= _RF_CONTENT_LENGTH
            if value is not None:
                try:
                    value = int(value, 10)
                except (TypeError, ValueError):
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
                len_value = len(value)
                flags &= ~ _RF_TRANSFER_CHUNKED
                if len_value == 7:
                    if _equals_ci(value, _CHUNKED, 7):
                        flags |= _RF_TRANSFER_CHUNKED
                elif len_value > 7:
                    if _lower(value).endswith(_CHUNKED):
                        flags |= _RF_TRANSFER_CHUNKED

        self._length = length
        self._flags = flags

    def endheaders(self, body=None, *, encode_chunked=None):
        if self._state != _CS_REQUEST_BUILDING:
            raise CannotSendHeader()

        try:
            body = self._prep_request(body, encode_chunked)
        except Exception:
            self._reset_request()
            raise

        try:
            if self._sock is None:
                self._open_socket()
            self._send_bytes(self._head, False)
            self._count = 0
            self._state = _CS_REQUEST_HEAD_OPEN
            self._send_body(body)
        except Exception:
            self._abort_request()
            raise
        finally:
            if _RECYCLE_HEADER_BUFFER and self._head is not None and len(self._head) <= _REQUEST_HEAD_SIZE:
                self._head[:] = b""
            else:
                self._head = None

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

    def getresponse(self, *, all_headers=False, and_cookies=None):
        state = self._state
        if (self._resp is not None or
                (state != _CS_REQUEST_HEAD_OPEN and
                 state != _CS_REQUEST_BODY_OPEN and
                 state != _CS_RESPONSE_ACTIVE)):
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

            status = None
            if _GC_FREE_THRESHOLD and gc.mem_free() < _GC_FREE_THRESHOLD:
                gc.collect()

            try:
                while True:
                    version, status, reason = _parse_status_line(self._sock)
                    response_headers = _parse_headers(self._sock, status, False if status == 100 else all_headers, and_cookies)
                    if status != 100:
                        break
            except OSError as e:
                raise IncompleteRead(_errno(e.errno), "socket read failed", None, None, status)

            response_chunked, response_length, reusable = _derive_response_framing(
                self.method, version, status, response_headers)

            if status < 200 and status != 101:
                sock = owner = None
                if not reusable:
                    self._flags |= _RF_CONNECTION_CLOSE
            else:
                sock = self._sock
                reusable = reusable and not (self._flags & _RF_CONNECTION_CLOSE)
                owner = self

            resp = self.response_class(
                owner, sock, self.method, self.url,
                version, status, reason, response_headers,
                response_chunked, response_length)

            if sock is None:
                return resp

            self._sock = None
            self._resp = resp
            if reusable:
                self._state = _CS_RESPONSE_REUSABLE

            if response_length == 0 and status != 101:
                resp.close()

            return resp
        except Exception:
            self._abort_request(resp)
            raise

    def _append_header(self, name, value):
        self._head.extend(name)
        self._head.extend(b": ")
        self._head.extend(value)
        self._head.extend(b"\r\n")

    def _prep_request(self, body, encode_chunked):
        if isinstance(body, str):
            body = body.encode()

        flags = self._flags
        length = self._length

        if encode_chunked is not None:
            chunked = bool(encode_chunked)
        elif flags & _RF_TRANSFER_ENCODING:
            chunked = bool(flags & _RF_TRANSFER_CHUNKED)
        elif flags & _RF_CONTENT_LENGTH:
            chunked = False
        elif isinstance(body, _BUFFER_TYPE):
            chunked = False
            length = len(body)
        else:
            chunked = body is not None

        self._chunked = chunked

        if not (flags & _RF_TRANSFER_ENCODING):
            if chunked:
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

    def _send_body(self, body):
        send = self._send_chunk if self._chunked else self._send_bytes

        if callable(body):
            body = body()

        if body is None:
            return

        if self._state == _CS_REQUEST_HEAD_OPEN:
            self._send_bytes(b"\r\n", False)
            self._state = _CS_REQUEST_BODY_OPEN

        if isinstance(body, str):
            body = body.encode()

        if isinstance(body, _BUFFER_TYPE):
            send(body)
            return

        reader = getattr(body, "readinto", None)
        if callable(reader):
            buf = bytearray(_READ_BLOCK_SIZE)
            bmv = memoryview(buf)
            while True:
                n = reader(buf)
                if type(n) is not int or n < 0 or n > _READ_BLOCK_SIZE:
                    raise TypeError("invalid body part")
                if not n:
                    return
                send(bmv if n == _READ_BLOCK_SIZE else bmv[:n])

        reader = getattr(body, "read", None)
        if callable(reader):
            while True:
                buf = reader(_READ_BLOCK_SIZE)
                if isinstance(buf, str):
                    buf = buf.encode()
                if not isinstance(buf, _BUFFER_TYPE):
                    raise TypeError("invalid body part")
                if not buf:
                    return
                send(buf)

        for part in body:
            if isinstance(part, str):
                part = part.encode()
            if not isinstance(part, _BUFFER_TYPE):
                raise TypeError("invalid body part")
            send(part)

    def _send_bytes(self, data, accounting=True):
        if self._sock is None:
            raise NotConnected()
        if not data:
            return

        try:
            self._sock.sendall(data)
        except OSError as e:
            raise IncompleteWrite(
                _errno(e.errno),
                "socket write failed",
                self._count,
                self._length)

        if accounting:
            self._count += len(data)

    def _send_chunk(self, data):
        if not data:
            return
        self._send_bytes(b"%X\r\n" % len(data), False)
        self._send_bytes(data)
        self._send_bytes(b"\r\n", False)

    def _open_socket(self):
        try:
            network = self._network
            if network is not None:
                try:
                    ready = network()
                except (MemoryError, OSError):
                    raise
                except Exception as e:
                    raise OSError(_ENETDOWN, str(e))
                if not ready:
                    raise OSError(_ENETUNREACH, "network unreachable")

            if _GC_FREE_THRESHOLD and gc.mem_free() < _GC_FREE_THRESHOLD:
                gc.collect()
            self._sock = create_connection((self._hostaddr, self.port), self._timeout)
        except OSError as e:
            raise ConnectError(_errno(e.errno), str(e))

    def _reset_request(self):
        self._state = _CS_IDLE
        self._resp = None
        self.method = None
        self.url = None
        self._length = None
        self._count = None
        self._flags = 0
        self._chunked = False

        if _RECYCLE_HEADER_BUFFER and self._head is not None and len(self._head) <= _REQUEST_HEAD_SIZE:
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
            if resp_sock is not sock:
                _close_quietly(resp_sock)
            _close_quietly(sock)
            self._reset_request()

if _ENABLE_SSL:

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
            raw = self._sock
            gc.collect()
            try:
                if self._hostname:
                    self._sock = self._context.wrap_socket(raw, server_hostname=self._hostname)
                else:
                    self._sock = self._context.wrap_socket(raw)
            except Exception as e:
                self._sock = None
                _close_quietly(raw)
                if isinstance(e, MemoryError):
                    raise
                if isinstance(e, OSError):
                    raise ConnectError(_errno(e.errno), str(e))
                raise ConnectError(_ENONET, str(e))
            finally:
                gc.collect()
