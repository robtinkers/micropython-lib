# http/clientish.py
#
# Serious HTTP for tiny devices.

import micropython, socket, errno, gc
try:
    import ssl
except ImportError:
    ssl = None

HTTP_PORT = const(80)
HTTPS_PORT = const(443)
OK = const(200)

_DEFAULT_TIMEOUT = const(10)
_GC_FREE_THRESHOLD = const(32768)
_METHODS_EXPECTING_BODY = (b"PATCH", b"POST", b"PUT")
_READ_BLOCK_SIZE = const(2048)
_READ_MUST_RETURN_BYTES = const(0)
_RECYCLE_HEADER_BUFFER = const(0)
_REQUEST_HEAD_SIZE = const(1024)

_RF_HOST = const(1)
_RF_CONNECTION = const(2)
_RF_CONNECTION_CLOSE = const(4)
_RF_CONTENT_LENGTH = const(8)
_RF_ACCEPT_ENCODING = const(16)
_RF_TRANSFER_ENCODING = const(32)
_RF_TRANSFER_CHUNKED = const(64)

_CS_IDLE = const(0)
_CS_REQUEST_STARTED = const(1)
_CS_REQUEST_SENT = const(2)
_CS_RECEIVING_RESPONSE = const(3)
_CS_RESPONSE_ACTIVE = const(4)

_CR = b"\r"
_LF = b"\n"
_CRLF = b"\r\n"
_EMPTY = b""
_COLON = b":"
_LBRACKET = b"["
_RBRACKET = b"]"
_CHUNKED = b"chunked"
_CLOSE = b"close"

_ACCEPT_ENCODING = b"Accept-Encoding"
_CONNECTION = b"Connection"
_CONTENT_LENGTH = b"Content-Length"
_CONTENT_TYPE = b"Content-Type"
_HOST = b"Host"
_LOCATION = b"Location"
_SET_COOKIE = b"Set-Cookie"
_TRANSFER_ENCODING = b"Transfer-Encoding"

_KEEP_RESPONSE_HEADERS = {
    8: (_LOCATION,),
    10:(_SET_COOKIE, _CONNECTION),
    12:(_CONTENT_TYPE,),
    14:(_CONTENT_LENGTH,),
    17:(_TRANSFER_ENCODING,),
}

_CONNECTION_ERRNOS = (
    getattr(errno, "EPIPE", 32),
    getattr(errno, "ENETRESET", 102),
    errno.ECONNABORTED,
    errno.ECONNRESET,
    errno.ENOTCONN,
    getattr(errno, "ESHUTDOWN", 108),
    errno.ECONNREFUSED,
)

_NETWORK_ERRNOS = (
    getattr(errno, "ENONET", 64),
    getattr(errno, "ENETDOWN", 100),
    getattr(errno, "ENETUNREACH", 101),
    getattr(errno, "EHOSTDOWN", 112),
    errno.EHOSTUNREACH,
)

class HTTPException(Exception): pass

class InvalidURL(HTTPException): pass

class BadStatusLine(HTTPException): pass

class RemoteDisconnected(BadStatusLine): pass

class UnknownProtocol(BadStatusLine): pass

class IncompleteRead(HTTPException):
    def __init__(self, value, response_bytes, response_length):
        super().__init__(value)
        self.count = response_bytes
        self.length = response_length
        if type(response_bytes) is int and type(response_length) is int:
            self.expected = response_length - response_bytes
        else:
            self.expected = None

class ImproperConnectionState(HTTPException): pass

class CannotSendRequest(ImproperConnectionState): pass

class CannotSendHeader(ImproperConnectionState): pass

class ResponseNotReady(ImproperConnectionState): pass

class NotConnected(ImproperConnectionState): pass

class ConnectionError(OSError): pass

class NetworkError(OSError): pass

class TimeoutError(OSError): pass

def _reraise_transport_error(exc):
    if isinstance(exc, (ConnectionError, NetworkError, TimeoutError)):
        raise
    err = exc.errno
    if err in _CONNECTION_ERRNOS:
        raise ConnectionError(*exc.args)
    if err in _NETWORK_ERRNOS:
        raise NetworkError(*exc.args)
    if err == errno.ETIMEDOUT:
        raise TimeoutError(*exc.args)
    raise

def _reraise_body_error(exc):
    if exc.errno in _CONNECTION_ERRNOS:
        raise OSError(errno.EIO, str(exc))
    raise

def _encode_and_validate(x):
    if x is None:
        return None
    if isinstance(x, str):
        x = bytes(x)
    elif not isinstance(x, (bytes, bytearray, memoryview)):
        x = str(x).encode()
    if _CR in x or _LF in x:
        return None
    return x

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

@micropython.viper
def _looks_like_ip4(buf:ptr8, length:int) -> int:
    if length <= 0:
        return 0
    i = 0
    while i < length:
        b = buf[i]
        if not (b == 46 or (48 <= b and b <= 57)):
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
        raise OSError(errno.EHOSTUNREACH, str(e))

    exc = None
    for info in infos:
        f, t, p, _, a = info
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
        raise OSError(getattr(errno, "EHOSTDOWN", 112), "Host is down")
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
        if first == _CR or first == _LF:
            continue
        if first != b"H":
            raise BadStatusLine(first + b"...")
        line = sock.readline()
        if not line.endswith(_LF):
            break
        if not line.startswith(b"TTP/"):
            break

        parts = line.split(None, 2)
        if len(parts) == 3:
            version, status, reason = parts
        elif len(parts) == 2:
            version, status = parts
            reason = _EMPTY
        else:
            break

        if len(status) != 3 or not status.isdigit():
            break
        status = int(status, 10)
        if status < 100:
            break

        if version == b"TTP/1.0":
            return 10, status, reason
        elif version.startswith(b"TTP/1."):
            return 11, status, reason
        else:
            raise UnknownProtocol(first + version)

    raise BadStatusLine(first + line)

def _parse_headers(sock, all_headers=False, and_cookies=None):
    if and_cookies is None:
        and_cookies = all_headers

    headers = []
    while True:
        line = sock.readline()
        if not line:
            raise RemoteDisconnected()
        if not line.endswith(_LF):
            raise BadStatusLine(line)
        if line == _CRLF or line == _LF:
            return headers
        if line[0] <= 32:
            continue

        pos = line.find(_COLON)
        if pos == -1:
            continue

        name = None
        cands = _KEEP_RESPONSE_HEADERS.get(pos)
        if cands:
            for cand in cands:
                if _equals_ci(line, cand, pos):
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

        elif key is _TRANSFER_ENCODING:
            len_val = len(val)
            if len_val == 7:
                chunked = bool(_equals_ci(val, _CHUNKED, 7))
            elif len_val > 7:
                chunked = val.endswith(_CHUNKED)
            else:
                chunked = False

        elif key is _CONNECTION:
            if reusable is not False:
                len_val = len(val)
                if http10:
                    reusable = (len_val == 10 and _equals_ci(val, b"keep-alive", 10))
                elif len_val == 5:
                    reusable = not _equals_ci(val, _CLOSE, 5)
                elif len_val > 5:
                    reusable = not val.endswith(_CLOSE)

    if reusable is None:
        reusable = not http10

    if chunked and (http10 or length is not None):
        reusable = False

    if status == 101:
        return False, 0, False

    if method == b"CONNECT" and 200 <= status < 300:
        return False, None, False

    if status < 200 or status == 204 or status == 205:
        return False, 0, (reusable and chunked is None and length is None)

    if method == b"HEAD" or status == 304:
        return False, 0, (reusable and length != -1)

    if chunked:
        return True, None, reusable

    if length == -1:
        return False, None, False

    return False, length, (reusable and length is not None)

class HTTPResponse:

    def __init__(self, sock, method, url,
                 version, status, reason, response_headers):
        self._conn = None
        self._sock = sock
        self.method = method
        self.url = url
        self.version = version
        self.status = status
        self.reason = reason
        self._headers = response_headers

        self._response_chunked, self._response_length, self._reusable = (
            _derive_response_framing(
                method, version, status, response_headers)
        )

        self._chunk_bytes_left = None
        self._response_bytes = 0

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    @property
    def closed(self):
        return self._sock is None

    def getheaders(self):
        return iter(self._headers)

    def getheader(self, name, default=None, *, sep=b", "):
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
                result += sep + val
        return default if result is None else result

    def read(self, amt=None):
        return self._read_impl(None, amt)

    def readinto(self, buf):
        if buf is None:
            raise TypeError("buffer required")
        return self._read_impl(buf, None)

    def detach(self):
        sock = self._sock
        if sock is None:
            raise NotConnected()
        self._sock = None
        self._return_socket(sock, False)
        return sock

    def close(self):
        self._release_socket(self._reusable and
                             self._response_bytes == self._response_length)

    def _abort(self, value="aborted"):
        self._release_socket(False)
        raise IncompleteRead(value, self._response_bytes, self._response_length)

    def _release_socket(self, reusable):
        sock, self._sock = self._sock, None
        if sock is not None and not self._return_socket(sock, reusable):
            _close_quietly(sock)

    def _return_socket(self, sock, reusable):
        conn, self._conn = self._conn, None

        if (conn is None or
                conn._state != _CS_RESPONSE_ACTIVE or
                conn._resp is not self or conn._sock is not None):
            return False

        conn._resp = None
        conn._sock = sock if reusable else None
        conn._reset_request()
        return reusable

    def _iowrapper(self, func, *args):
        try:
            return func(*args)
        except Exception as e:
            self._release_socket(False)
            _reraise_transport_error(e)

    def _append_data(self, out, data):
        try:
            if not out:
                return data
            if type(out) is bytes:
                out = bytearray(out)
            out.extend(data)
            return out
        except MemoryError:
            self._release_socket(False)
            raise

    def _get_chunk_bytes_left(self):
        while True:
            if self._chunk_bytes_left is None:
                line = self._iowrapper(self._sock.readline)
                if not line:
                    self._abort()
                pos = line.find(b";")
                try:
                    if pos >= 0:
                        line = line[:pos]
                    size = int(line, 16)
                    if size < 0:
                        self._abort("negative chunk-size")
                except ValueError:
                    self._abort("malformed chunk-size")
                if size > 0:
                    self._chunk_bytes_left = size
                    return size
                while True:
                    line = self._iowrapper(self._sock.readline)
                    if (line == _CRLF or line == _LF):
                        self._response_length = self._response_bytes
                        self.close()
                        return 0
                    if not line:
                        self._abort()
            elif self._chunk_bytes_left == 0:
                line = self._iowrapper(self._sock.readline)
                if not line:
                    self._abort()
                if not (line == _CRLF or line == _LF):
                    self._abort("malformed terminator")
                self._chunk_bytes_left = None
            else:
                return self._chunk_bytes_left

    def _read_impl(self, buf, amt):
        sock = self._sock
        into = buf is not None
        if sock is None:
            if (self._response_length is not None and
                    self._response_bytes >= self._response_length):
                return 0 if into else _EMPTY
            raise NotConnected()

        if into:
            if not buf:
                return 0
            amt = len(buf)
            unbounded = False
        else:
            unbounded = amt is None or amt < 0
        if not unbounded and amt == 0:
            return 0 if into else _EMPTY

        if (self._response_length is not None):
            remaining = self._response_length - self._response_bytes
            if remaining == 0:
                self.close()
                return 0 if into else _EMPTY
            if unbounded:
                amt = remaining
                unbounded = False
            else:
                amt = min(amt, remaining)

        if into:
            if self._response_chunked:
                bmv = buf if isinstance(buf, memoryview) else memoryview(buf)
                total = 0
                while total < amt:
                    want = min(self._get_chunk_bytes_left(), amt - total)
                    if want == 0:
                        break
                    n = self._iowrapper(sock.readinto, bmv[total:], want)
                    if not n:
                        self._abort()
                    self._response_bytes += n
                    self._chunk_bytes_left -= n
                    total += n
                return total

            n = self._iowrapper(sock.readinto, buf, amt)
            if not n:
                if (self._response_length is None):
                    self._response_length = self._response_bytes
                    self.close()
                    return 0
                self._abort()

            self._response_bytes += n
            if (self._response_length is not None) and (self._response_bytes >= self._response_length):
                self.close()
            return n

        if self._response_chunked:
            out = _EMPTY
            len_out = 0
            while unbounded or len_out < amt:
                avail = self._get_chunk_bytes_left()
                if unbounded:
                    want = min(avail, _READ_BLOCK_SIZE)
                else:
                    want = min(amt - len_out, avail, _READ_BLOCK_SIZE)
                if want == 0:
                    break
                chunk = self._iowrapper(sock.read, want)
                if not chunk:
                    self._abort()
                len_chunk = len(chunk)
                self._response_bytes += len_chunk
                self._chunk_bytes_left -= len_chunk
                len_out += len_chunk
                out = self._append_data(out, chunk)
            if _READ_MUST_RETURN_BYTES and type(out) is not bytes:
                out = bytes(out)
            return out

        out = _EMPTY
        len_out = 0
        while unbounded or len_out < amt:
            if unbounded:
                want = _READ_BLOCK_SIZE
            else:
                want = min(amt - len_out, _READ_BLOCK_SIZE)
            data = self._iowrapper(sock.read, want)
            if not data:
                if (self._response_length is None):
                    self._response_length = self._response_bytes
                    self.close()
                    break
                self._abort()
            len_data = len(data)
            self._response_bytes += len_data
            len_out += len_data
            out = self._append_data(out, data)
            if (self._response_length is not None) and (self._response_bytes >= self._response_length):
                self.close()
                break
        if _READ_MUST_RETURN_BYTES and type(out) is not bytes:
            out = bytes(out)
        return out

class HTTPConnection:
    default_port = HTTP_PORT

    def __init__(self, host, port=None, *, timeout=_DEFAULT_TIMEOUT, network=None):
        self._set_authority(host, port)
        self._timeout = timeout
        self._network = network
        self._sock = None
        self._resp = None
        self._request_head = None
        self._reset_request()

    def _set_authority(self, host, port):
        the_host = _encode_and_validate(host)
        if not the_host:
            raise InvalidURL(host)

        hostaddr = the_host
        hostname = None
        colons = the_host.count(_COLON)

        if the_host.startswith(_LBRACKET):
            if colons < 2 or not the_host.endswith(_RBRACKET):
                raise InvalidURL(host)
            hostaddr = the_host[1:-1]
        elif colons == 1:
            raise InvalidURL(host)
        elif colons:
            the_host = _LBRACKET + the_host + _RBRACKET
        elif not _looks_like_ip4(the_host, len(the_host)):
            hostname = the_host

        if port is None:
            port = self.default_port

        if port == self.default_port:
            hostport = the_host
        else:
            hostport = b"%s:%d" % (the_host, port)

        self.host = the_host
        self._hostaddr = hostaddr
        self._hostname = hostname
        self._hostport = hostport
        self.port = port

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def connect(self):
        if self._state != _CS_IDLE:
            raise CannotSendRequest()
        self.close()
        try:
            self._open_socket()
        except Exception:
            self._abort_request()
            raise

    def close(self):
        _close_quietly(self.detach())

    def detach(self):
        resp = self._resp
        if resp is not None:
            sock = self._detach_response(resp)
        else:
            sock = self._sock
        self._sock = None
        self._reset_request()
        return sock

    def request(self, method, url, body=_EMPTY, headers=None, *, encode_chunked=None):
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
        self._state = _CS_REQUEST_STARTED
        try:
            method = _encode_and_validate(method)
            if not method:
                raise ValueError("bad method")
            if type(method) is not bytes:
                method = bytes(method)
            if not method.isupper():
                method = method.upper()

            if url:
                valid_url = _encode_and_validate(url)
            else:
                valid_url = b"/"
            if not valid_url:
                raise InvalidURL(url)
            if type(valid_url) is not bytes:
                valid_url = bytes(valid_url)

            self.method = method
            self.url = valid_url

            if self._request_head is None:
                self._request_head = bytearray(_REQUEST_HEAD_SIZE)
                self._request_head[:] = _EMPTY
            self._request_head.extend(method)
            self._request_head.extend(b" ")
            self._request_head.extend(valid_url)
            self._request_head.extend(b" HTTP/1.1\r\n")

            if skip_host:
                self._request_flags |= _RF_HOST
            if skip_accept_encoding:
                self._request_flags |= _RF_ACCEPT_ENCODING
        except Exception:
            self._reset_request()
            raise

    def putheader(self, name, value):
        if self._state != _CS_REQUEST_STARTED:
            raise CannotSendHeader()

        name = _encode_and_validate(name)
        if name is None:
            raise ValueError("invalid header name")
        if value is not None:
            value = _encode_and_validate(value)
            if value is None:
                raise ValueError("invalid header value")
            self._append_header(name, value)
        self._track_request_header(name, value)

    def endheaders(self, body=_EMPTY, *, encode_chunked=None):
        if self._state != _CS_REQUEST_STARTED:
            raise CannotSendHeader()

        try:
            body = self._prep_request(body, encode_chunked)
        except Exception:
            self._reset_request()
            raise

        try:
            if self._sock is None:
                self._open_socket()
            self._send_bytes(self._request_head, False)
            self._send_bytes(_CRLF, False)
            if _RECYCLE_HEADER_BUFFER:
                self._request_head[:] = _EMPTY
            else:
                self._request_head = None
            self._state = _CS_REQUEST_SENT
        except Exception:
            self._abort_request()
            raise

        self.send(body)

    def send(self, body):
        if self._state != _CS_REQUEST_SENT:
            raise CannotSendRequest()
        if self._sock is None:
            raise NotConnected()

        try:
            if isinstance(body, str):
                body = bytes(body)
            self._send_body(body)
        except Exception:
            self._abort_request()
            raise

    def getresponse(self, *, all_headers=False, and_cookies=None):
        state = self._state
        if state != _CS_REQUEST_SENT and state != _CS_RECEIVING_RESPONSE:
            raise ResponseNotReady()
        if self._sock is None:
            raise NotConnected()

        resp = None
        try:
            if state == _CS_REQUEST_SENT:
                self._state = _CS_RECEIVING_RESPONSE
                if self._request_chunked:
                    self._send_bytes(b"0\r\n\r\n", False)
                elif (self._request_length is not None and
                      self._request_bytes != self._request_length):
                    raise ImproperConnectionState(
                        "request body length differs from Content-Length",
                        self._request_bytes,
                        self._request_length)

            try:
                version, status, reason = _parse_status_line(self._sock)
                response_headers = _parse_headers(self._sock, all_headers, and_cookies)
            except OSError as e:
                _reraise_transport_error(e)

            if _GC_FREE_THRESHOLD and gc.mem_free() < _GC_FREE_THRESHOLD:
                gc.collect()

            resp = HTTPResponse(
                self._sock, self.method, self.url,
                version, status, reason, response_headers)

            if status < 200 and status != 101:
                resp._sock = None
                if not resp._reusable:
                    self._request_flags |= _RF_CONNECTION_CLOSE
                return resp

            self._sock = None
            resp._reusable = resp._reusable and not (self._request_flags & _RF_CONNECTION_CLOSE)

            if resp._reusable:
                self._resp = resp
                resp._conn = self
                self._state = _CS_RESPONSE_ACTIVE
            else:
                self._reset_request()

            if resp._response_length == 0 and status != 101:
                resp.close()

            return resp
        except Exception:
            self._abort_request(resp)
            raise

    def _append_header(self, name, value):
        self._request_head.extend(name)
        self._request_head.extend(b": ")
        self._request_head.extend(value)
        self._request_head.extend(_CRLF)

    def _track_request_header(self, name, value):
        len_name = len(name)
        length = self._request_length
        flags = self._request_flags

        if len_name == 4:
            if _equals_ci(name, _HOST, 4):
                flags |= _RF_HOST
        elif len_name == 10:
            if _equals_ci(name, _CONNECTION, 10):
                flags |= _RF_CONNECTION
                if value is not None:
                    len_value = len(value)
                    if ((len_value == 5 and _equals_ci(value, _CLOSE, 5)) or
                            (len_value > 5 and value.endswith(_CLOSE))):
                        flags |= _RF_CONNECTION_CLOSE
        elif len_name == 14:
            if _equals_ci(name, _CONTENT_LENGTH, 14):
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
        elif len_name == 15:
            if _equals_ci(name, _ACCEPT_ENCODING, 15):
                flags |= _RF_ACCEPT_ENCODING
        elif len_name == 17:
            if _equals_ci(name, _TRANSFER_ENCODING, 17):
                flags |= _RF_TRANSFER_ENCODING
                if value is not None:
                    len_value = len(value)
                    flags &= ~ _RF_TRANSFER_CHUNKED
                    if len_value == 7 and _equals_ci(value, _CHUNKED, 7):
                        flags |= _RF_TRANSFER_CHUNKED
                    elif len_value > 7 and value.endswith(_CHUNKED):
                        flags |= _RF_TRANSFER_CHUNKED

        self._request_length = length
        self._request_flags = flags

    def _prep_request(self, body, encode_chunked):
        if isinstance(body, str):
            body = bytes(body)

        flags = self._request_flags
        length = self._request_length

        if encode_chunked is not None:
            chunked = bool(encode_chunked)
        elif flags & _RF_TRANSFER_ENCODING:
            chunked = flags & _RF_TRANSFER_CHUNKED
        elif flags & _RF_CONTENT_LENGTH:
            chunked = False
        elif isinstance(body, (bytes, bytearray, memoryview)):
            chunked = False
            length = len(body)
        else:
            chunked = body is not None

        self._request_chunked = chunked

        if not (flags & _RF_TRANSFER_ENCODING):
            if chunked:
                self._append_header(_TRANSFER_ENCODING, _CHUNKED)
            elif not (flags & _RF_CONTENT_LENGTH):
                if (length is not None and length >= 0 and
                        (length or self.method in _METHODS_EXPECTING_BODY)):
                    self._append_header(_CONTENT_LENGTH, b"%d" % length)

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
        self._request_length = length

        return body

    def _send_body(self, body):
        send = self._send_chunk if self._request_chunked else self._send_bytes

        try:
            if callable(body):
                body = body()
        except OSError as e:
            _reraise_body_error(e)

        if body is None:
            return

        if isinstance(body, (bytes, bytearray, memoryview)):
            send(body)
            return

        reader = getattr(body, "readinto", None)
        if callable(reader):
            buf = bytearray(_READ_BLOCK_SIZE)
            bmv = memoryview(buf)
            while True:
                try:
                    n = reader(buf)
                except OSError as e:
                    _reraise_body_error(e)
                if n is None:
                    continue
                if type(n) is not int or n < 0 or n > _READ_BLOCK_SIZE:
                    raise TypeError("invalid body part")
                if not n:
                    return
                send(bmv if n == _READ_BLOCK_SIZE else bmv[:n])

        reader = getattr(body, "read", None)
        if callable(reader):
            while True:
                try:
                    buf = reader(_READ_BLOCK_SIZE)
                except OSError as e:
                    _reraise_body_error(e)
                if buf is None:
                    continue
                if isinstance(buf, str):
                    buf = bytes(buf)
                if not isinstance(buf, (bytes, bytearray, memoryview)):
                    raise TypeError("invalid body part")
                if not buf:
                    return
                send(buf)

        try:
            parts = iter(body)
        except OSError as e:
            _reraise_body_error(e)

        while True:
            try:
                part = next(parts)
            except StopIteration:
                return
            except OSError as e:
                _reraise_body_error(e)

            if isinstance(part, str):
                part = bytes(part)
            if not isinstance(part, (bytes, bytearray, memoryview)):
                raise TypeError("invalid body part")
            send(part)

    def _send_bytes(self, data, accounting=True):
        if self._sock is None:
            raise NotConnected()
        if not data:
            return

        try:
            self._sock.sendall(data)
            if accounting is True:
                self._request_bytes += len(data)
        except OSError as e:
            _reraise_transport_error(e)

    def _send_chunk(self, data, accounting=True):
        if not data:
            return
        self._send_bytes(b"%X\r\n" % len(data), False)
        self._send_bytes(data, accounting)
        self._send_bytes(_CRLF, False)

    def _open_socket(self):
        network = self._network
        if network is not None:
            try:
                ready = network()
            except OSError as e:
                raise NetworkError(*e.args)
            except Exception as e:
                raise NetworkError(getattr(errno, "ENONET", 64), str(e))
            if not ready:
                raise NetworkError(getattr(errno, "ENETDOWN", 100), "Network is down")
        if _GC_FREE_THRESHOLD and gc.mem_free() < _GC_FREE_THRESHOLD:
            gc.collect()
        try:
            self._sock = create_connection(
                (self._hostaddr, self.port), self._timeout)
        except OSError as e:
            _reraise_transport_error(e)

    def _reset_request(self):
        self._state = _CS_IDLE
        self.method = None
        self.url = None
        self._request_length = None
        self._request_bytes = 0
        self._request_flags = 0
        self._request_chunked = False
        if _RECYCLE_HEADER_BUFFER and self._request_head is not None:
            self._request_head[:] = _EMPTY
        else:
            self._request_head = None

    def _abort_request(self, resp=None):
        try:
            if resp is None:
                resp = self._resp
            if resp is not None:
                _close_quietly(self._detach_response(resp))

            sock, self._sock = self._sock, None
            _close_quietly(sock)
        finally:
            self._reset_request()

    def _detach_response(self, resp):
        sock, resp._sock = resp._sock, None
        self._resp = None
        resp._conn = None
        return sock

if ssl is not None:

    class HTTPSConnection(HTTPConnection):
        default_port = HTTPS_PORT

        def __init__(self, *args, context=None, **kwargs):
            super().__init__(*args, **kwargs)
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
                _reraise_transport_error(e)
            finally:
                gc.collect()
