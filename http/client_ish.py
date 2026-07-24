# http/client_ish.py

import micropython, socket, errno, gc

HTTP_PORT = const(80)
HTTPS_PORT = const(443)
OK = const(200)

_DEFAULT_TIMEOUT = const(10)
_METHODS_EXPECTING_BODY = (b"PATCH", b"POST", b"PUT")
_GC_FREE_THRESHOLD = const(32768)

_RF_HOST = const(1)
_RF_CONNECTION = const(2)
_RF_CONNECTION_CLOSE = const(4)
_RF_CONTENT_LENGTH = const(8)
_RF_ACCEPT_ENCODING = const(16)
_RF_TRANSFER_ENCODING = const(32)
_RF_TRANSFER_CHUNKED = const(64)

_CR = b"\r"
_LF = b"\n"
_CRLF = b"\r\n"
_EMPTY = b""

_ACCEPT_ENCODING = b"Accept-Encoding"
_CHUNKED = b"chunked"
_CONNECTION = b"Connection"
_CONTENT_LENGTH = b"Content-Length"
_HOST = b"Host"
_SET_COOKIE = b"Set-Cookie"
_TRANSFER_ENCODING = b"Transfer-Encoding"

_CONNECTION_ERRNOS = (
    errno.ECONNABORTED,
    errno.ECONNREFUSED,
    errno.ECONNRESET,
    getattr(errno, "EPIPE", errno.ECONNABORTED),
    getattr(errno, "ESHUTDOWN", errno.ECONNRESET),
)

class HTTPException(Exception): pass

class NotConnected(HTTPException): pass

class InvalidURL(HTTPException): pass

class BadStatusLine(HTTPException): pass

class RemoteDisconnected(BadStatusLine): pass

class UnknownProtocol(BadStatusLine): pass

class IncompleteRead(HTTPException):
    def __init__(self, value, partial, length):
        super().__init__(value, partial, length)
        self.value = value
        self.partial = partial
        self.length = length
        if partial is not None and length is not None:
            self.expected = length - partial
        else:
            self.expected = None

class ImproperConnectionState(HTTPException): pass

class ConnectionError(OSError): pass

class TimeoutError(OSError):
    def __init__(self, *args):
        OSError.__init__(self, errno.ETIMEDOUT, *args)

class NetworkError(Exception): pass

def _reraise_transport_error(exc):
    err = getattr(exc, "errno", None)
    if err == errno.ETIMEDOUT:
        raise TimeoutError()
    if err == errno.ENOTCONN:
        raise NotConnected()
    if err in _CONNECTION_ERRNOS:
        raise ConnectionError(*exc.args)
    raise

def _reraise_body_error(exc):
    err = getattr(exc, "errno", None)
    if err in _CONNECTION_ERRNOS:
        raise OSError(errno.EIO, str(exc))
    raise

_generator = lambda: (yield)

def isgeneratorfunction(obj):
    return isinstance(obj, type(_generator))

@micropython.viper
def _validate(buf:ptr8, start:int, end:int, flags:int) -> int:
    i = start
    while i < end:
        b = buf[i]
        if flags & 256:
            if not(b == 46 or (48 <= b and b <= 57)):
                return 0
        elif b == 9:
            if flags & 2:
                return 0
        elif b < 32:
            return 0
        elif b == 32:
            if flags & 1:
                return 0
        elif b == 58:
            if flags & 16:
                return 0
        elif b == 127:
            return 0
        i += 1
    return 1

def _encode_and_validate(x, flags):
    if isinstance(x, str):
        x = x.encode()
    elif not isinstance(x, (bytes, bytearray, memoryview)):
        x = str(x).encode()
    if not _validate(x, 0, len(x), flags):
        raise ValueError("invalid character")
    return x

def decode_latin1(buf, default=None):
    return default if buf is None else buf.decode()

@micropython.viper
def _lower_case(buf:ptr8, start:int, end:int, out:ptr8) -> int:
    write = int(out) != 0
    i = start
    while i < end:
        b = buf[i]
        if write:
            if 65 <= b and b <= 90:
                b += 32
            out[i - start] = b
        else:
            if 65 <= b and b <= 90:
                return 0
        i += 1
    return 1

def normalize_header_name(buf, start=0, end=None):
    if isinstance(buf, str):
        buf = buf.encode()
    elif not isinstance(buf, (bytes, bytearray, memoryview)):
        return None
    if end is None:
        end = len(buf)
    if not _validate(buf, start, end, 19):
        return None
    if _lower_case(buf, start, end, 0):
        if start == 0 and end == len(buf):
            return buf
        return buf[start:end]
    out = bytearray(end - start)
    _lower_case(buf, start, end, out)
    return out

@micropython.viper
def _equalsci(a:ptr8, b:ptr8, length:int) -> int:
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

def create_connection(address, timeout=None, *, resolver=None, error=NetworkError):
    host, port = address
    if resolver is None:
        resolver = socket.getaddrinfo
    try:
        infos = iter(resolver(host, port, 0, socket.SOCK_STREAM))
    except Exception as e:
        raise error(str(e))
    exc, msg = None, None
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
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            except (AttributeError, OSError):
                pass
            sock.connect(a)
            return sock
        except OSError as e:
            if exc is None and msg is None:
                msg = str(e)
            _close_quietly(sock)
        except Exception as e:
            if exc is None:
                exc = e
            msg = None
            _close_quietly(sock)
    if exc is not None:
        raise exc
    raise OSError(errno.EHOSTUNREACH, msg)

_keep_response_headers = {
    4:[b"etag"],
    8:[b"location"],
    10:[_SET_COOKIE, _CONNECTION],
    11:[b"retry-after"],
    12:[b"content-type"],
    14:[_CONTENT_LENGTH],
    16:[b"content-encoding", b"www-authenticate"],
    17:[_TRANSFER_ENCODING],
}

def _parse_headers(readline, all_headers=False, and_cookies=None):
    if and_cookies is None:
        and_cookies = all_headers
    headers = []
    while True:
        line = readline()

        if line == _CRLF or line == _LF:
            return headers

        if not line or not line.endswith(_LF):
            raise BadStatusLine()

        if line[0] <= 32:
            continue

        sep = line.find(b":")
        if sep == -1:
            continue

        if sep == 0 or line[sep - 1] <= 32:
            raise HTTPException("invalid header")
        end = sep

        name = None

        cands = _keep_response_headers.get(end)
        if cands is not None:
            for cand in cands:
                if _equalsci(line, cand, end):
                    name = cand
                    break

        if name is None:
            if not all_headers:
                continue
            name = normalize_header_name(line, 0, end)
            if name is None:
                continue
            if not isinstance(name, bytes):
                name = bytes(name)
        elif name == _SET_COOKIE and not and_cookies:
            continue

        start, end = sep + 1, len(line)
        while start < end and line[start] <= 32: start += 1
        while end > start and line[end - 1] <= 32: end -= 1
        headers.append(name)
        headers.append(line[start:end])

def _parse_authority(host, port, default_port):
    rest = ""
    if host.startswith("["):
        j = host.find("]")
        if j == -1:
            raise InvalidURL()
        normalized_host, rest = host[:j+1], host[j+1:]
        if rest:
            if not rest.startswith(":"):
                raise InvalidURL()
            rest = rest[1:]
        hostaddr = normalized_host[1:-1]
        hostname = None
    elif host.count(":") > 1:
        normalized_host = "[" + host + "]"
        hostaddr = host
        hostname = None
    else:
        i = host.find(":")
        if i >= 0:
            normalized_host, rest = host[:i], host[i+1:]
        else:
            normalized_host = host
        len_host = len(normalized_host)
        if (len_host > 0 and
                _validate(normalized_host, 0, len_host, 256)):
            hostaddr = normalized_host
            hostname = None
        else:
            hostaddr = normalized_host
            hostname = normalized_host

    if rest:
        if rest.isdigit():
            port = int(rest, 10)
        else:
            raise InvalidURL()

    if port is None or port == default_port:
        hostport = normalized_host.encode()
        port = default_port
    else:
        hostport = b"%s:%d" % (normalized_host, port)

    return normalized_host, hostaddr, hostname, hostport, port

def _determine_response_framing(method, http_version, status, response_headers):
    http10 = (http_version == 10)
    content_length_value = None
    transfer_encoding_chunked = None
    reusable = None

    for i in range(0, len(response_headers), 2):
        name = response_headers[i]
        value = response_headers[i+1]
        len_value = len(value)

        if name == _CONTENT_LENGTH:
            try:
                value = int(value, 10)
            except (TypeError, ValueError):
                value = -1

            if value < 0:
                content_length_value = -1
            elif content_length_value is None:
                content_length_value = value
            elif content_length_value != value:
                content_length_value = -1

        elif name == _TRANSFER_ENCODING:
            transfer_encoding_chunked = (len_value == 7) and _equalsci(value, _CHUNKED, 7)

        elif name == _CONNECTION:
            if (len_value == 5) and _equalsci(value, b"close", 5):
                reusable = False
            elif (
                (len_value == 10) and _equalsci(value, b"keep-alive", 10)
                and reusable is None and http10
            ):
                reusable = True

    if reusable is None:
        reusable = not http10

    if method == b"HEAD" or status == 304:
        transfer_encoding_chunked = False
        content_length_value = 0

    elif 100 <= status < 200 or status == 204:
        if transfer_encoding_chunked is not None:
            reusable = False
        transfer_encoding_chunked = False
        content_length_value = 0

    elif transfer_encoding_chunked is None:
        transfer_encoding_chunked = False
        if content_length_value is None:
            reusable = False
        elif content_length_value < 0:
            reusable = False
            content_length_value = None

    else:
        if not transfer_encoding_chunked or content_length_value is not None or http10:
            reusable = False
        content_length_value = None

    return transfer_encoding_chunked, content_length_value, reusable

class HTTPResponse:
    _blocksize = 2048

    def __init__(self, sock, method, url, http_version, status, reason,
                 response_headers, *, decode_chunked=None):
        self._sock = sock
        self._conn = None
        self._headers = response_headers

        self.method = method
        self.url = url
        self.version = http_version
        self.status = status
        self._reason = reason

        self._response_chunked, self._response_length, self._reusable = (
            _determine_response_framing(
                method, http_version, status, response_headers)
        )

        if decode_chunked is not None and self._response_chunked != decode_chunked and self._response_length != 0:
            self._response_chunked = bool(decode_chunked)
            self._response_length = None
            self._reusable = False

        self._chunk_left = None
        self._response_bytes = 0

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        return False

    @property
    def length(self):
        return None if self._response_length is None else self._response_length - self._response_bytes

    @property
    def reason(self):
        return decode_latin1(self._reason.strip(), "")

    def getheaders(self):
        out = []
        headers = self._headers
        for i in range(0, len(headers), 2):
            try:
                out.append((decode_latin1(headers[i]),
                            decode_latin1(headers[i+1])))
            except UnicodeError:
                pass
        return out

    def iter_rawheaders(self):
        headers = self._headers
        for i in range(0, len(headers), 2):
            yield headers[i], headers[i+1]

    def getheader(self, name, default=None):
        return decode_latin1(self.rawheader(name, None), default)

    def rawheader(self, name, default=None, *, join=b", "):
        if isinstance(name, str):
            name = name.encode()
        len_name = len(name)
        result = None
        for i in range(0, len(self._headers), 2):
            key = self._headers[i]
            if len(key) == len_name and _equalsci(name, key, len_name):
                if result is None:
                    result = self._headers[i+1]
                else:
                    result += join + self._headers[i+1]
        return default if result is None else result

    def read(self, amt=None):
        return self._read_impl(None, amt)

    def readinto(self, buf):
        if buf is None:
            raise TypeError("buffer required")
        return self._read_impl(buf, None)

    def iter_content_into(self, bmv):
        if not isinstance(bmv, memoryview):
            bmv = memoryview(bmv)
        if not bmv:
            raise ValueError("buffer must not be empty")
        while True:
            n = self.readinto(bmv)
            if n == 0:
                return
            yield n

    def close(self):
        reusable = (self._reusable and self.status != 101 and self._response_bytes == self._response_length)
        self._finish_response(reusable)

    def abort(self, value="aborted"):
        self._finish_response(False)
        raise IncompleteRead(value, self._response_bytes, self._response_length)

    def detach(self):
        sock, self._sock = self._sock, None
        self._return_socket_to_connection(sock, False)
        return sock

    def _finish_response(self, reusable):
        sock = self._sock
        if sock is None:
            return

        self._sock = None
        reusable = self._return_socket_to_connection(sock, reusable)
        if not reusable:
            _close_quietly(sock)

    def _return_socket_to_connection(self, sock, reusable):
        conn = self._conn
        if conn is None:
            return False

        self._conn = None
        if conn._resp is not self or conn._sock is not sock:
            return False

        conn._resp = None
        if not reusable:
            conn._sock = None
        conn._reset_request()
        return reusable

    def _call_body_io(self, func, *args):
        loops = 3
        while loops > 0:
            loops -= 1
            try:
                return func(*args)
            except OSError as e:
                err = getattr(e, "errno", None)
                if err == errno.EINTR and loops > 0:
                    continue
                self._finish_response(False)
                if err == errno.EINTR:
                    raise
                _reraise_transport_error(e)
            except Exception:
                self._finish_response(False)
                raise

    def _get_chunk_left(self):
        while True:
            if self._chunk_left is None:
                line = self._call_body_io(self._sock.readline)
                if not line:
                    self.abort()
                sep = line.find(b";")
                try:
                    if sep >= 0:
                        line = line[:sep]
                    size = int(line, 16)
                    if size < 0:
                        self.abort("negative chunk-size")
                except MemoryError:
                    self._finish_response(False)
                    raise
                except ValueError:
                    self.abort("malformed chunk-size")
                if size > 0:
                    self._chunk_left = size
                    return size
                while True:
                    line = self._call_body_io(self._sock.readline)
                    if line == _CRLF or line == _LF:
                        self._response_chunked = False
                        self._response_length = self._response_bytes
                        self.close()
                        return 0
                    if not line:
                        self.abort()
            elif self._chunk_left == 0:
                line = self._call_body_io(self._sock.readline)
                if not line:
                    self.abort()
                if line != _CRLF and line != _LF:
                    self.abort("malformed terminator")
                self._chunk_left = None
            else:
                return self._chunk_left

    def _append_read_data(self, out, data):
        try:
            if out is _EMPTY:
                return data
            if type(out) is bytes:
                out = bytearray(out)
            out.extend(data)
            return out
        except MemoryError:
            self._finish_response(False)
            raise

    def _read_impl(self, buf, amt):
        into = buf is not None
        sock = self._sock

        if sock is None:
            if (self._response_length is not None and
                    self._response_bytes == self._response_length):
                return 0 if into else _EMPTY
            raise NotConnected()

        if into and not buf:
            return 0
        if into:
            amt = len(buf)
            unbounded = False
        else:
            unbounded = amt is None or amt < 0

        if not unbounded and amt == 0:
            return 0 if into else _EMPTY

        length = self._response_length
        if length is not None:
            remaining = length - self._response_bytes
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
                    want = min(self._get_chunk_left(), amt - total)
                    if want == 0:
                        break
                    target = bmv[total:]
                    n = self._call_body_io(sock.readinto, target, want)
                    if not n:
                        self.abort()
                    self._response_bytes += n
                    self._chunk_left -= n
                    total += n
                return total

            n = self._call_body_io(sock.readinto, buf, amt)
            if not n:
                if self._response_length is None:
                    self._response_length = self._response_bytes
                    self.close()
                    return 0
                self.abort()

            self._response_bytes += n
            if length is not None and self._response_bytes >= length:
                self.close()
            return n

        if self._response_chunked:
            out = _EMPTY
            len_out = 0
            while unbounded or len_out < amt:
                avail = self._get_chunk_left()
                if unbounded:
                    want = min(avail, self._blocksize)
                else:
                    want = min(amt - len_out, avail, self._blocksize)
                if want == 0:
                    break
                chunk = self._call_body_io(sock.read, want)
                if not chunk:
                    self.abort()
                len_chunk = len(chunk)
                self._response_bytes += len_chunk
                self._chunk_left -= len_chunk
                len_out += len_chunk
                out = self._append_read_data(out, chunk)
            return out

        out = _EMPTY
        len_out = 0
        while unbounded or len_out < amt:
            if unbounded:
                want = self._blocksize
            else:
                want = min(amt - len_out, self._blocksize)
            data = self._call_body_io(sock.read, want)
            if not data:
                if self._response_length is None:
                    self._response_length = self._response_bytes
                    self.close()
                    break
                self.abort()
            len_data = len(data)
            self._response_bytes += len_data
            len_out += len_data
            out = self._append_read_data(out, data)
            if length is not None and self._response_bytes >= length:
                self.close()
                break
        return out

class HTTPConnection:
    default_port = HTTP_PORT
    _blocksize = 2048
    _request_head_size = 1024

    def __init__(self, host, port=None, timeout=_DEFAULT_TIMEOUT,
                 *, blocksize=None, network=None):
        (self.host,
         self._hostaddr,
         self._hostname,
         self._hostport,
         self.port) = _parse_authority(host, port, self.default_port)
        self.timeout = timeout
        if blocksize is not None:
            if blocksize <= 0:
                raise ValueError("blocksize must be positive")
            self._blocksize = blocksize
        self._network = network
        self._sock = None
        self._resp = None
        self._request_head = None
        self._reset_request()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        return False

    def connect(self):
        self.close()
        self._open_socket()

    def close(self):
        sock = self.detach()
        _close_quietly(sock)

    def detach(self):
        self._reset_request()
        resp = self._resp
        if resp is not None:
            self._sever_response(resp)
        sock, self._sock = self._sock, None
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

    def putrequest(self, method, url, *, skip_host=False):
        self._reset_request()
        try:
            method = _encode_and_validate(method, 3)
            if not method:
                raise ValueError("bad method")
            if not isinstance(method, bytes):
                method = bytes(method)
            if not method.isupper():
                method = method.upper()

            if url:
                url = _encode_and_validate(url, 3)
                if not isinstance(url, bytes):
                    url = bytes(url)
            else:
                url = b"/"

            self.method = method
            self.url = url

            if self._request_head is None:
                self._request_head = bytearray(self._request_head_size)
                self._request_head[:] = _EMPTY
            self._request_head.extend(method)
            self._request_head.extend(b" ")
            self._request_head.extend(url)
            self._request_head.extend(b" HTTP/1.1\r\n")

            if skip_host:
                self._request_flags |= _RF_HOST
        except Exception:
            self._reset_request()
            raise

    def putheader(self, name, value):
        try:
            name = _encode_and_validate(name, 19)
            if value is not None:
                value = _encode_and_validate(value, 0)
                self._append_header(name, value)
            self._track_request_header(name, value)
        except Exception:
            self._reset_request()
            raise

    def endheaders(self, body=None, *, encode_chunked=None):
        try:
            body = self._prep_request(body, encode_chunked)
        except Exception:
            self._reset_request()
            raise

        try:
            if self._sock is None:
                self._open_socket()
            self._send_raw(self._request_head, False)
            self._send_raw(_CRLF, False)
            self._send_request_body(body)
        except Exception:
            self._abort_attempt()
            raise

    def _prep_request(self, body, encode_chunked):
        if isinstance(body, str):
            body = body.encode()
        flags = self._request_flags

        if encode_chunked is None:
            self._request_chunked = bool(flags & _RF_TRANSFER_CHUNKED)
        else:
            self._request_chunked = bool(encode_chunked)

        if self._request_length is not None and self._request_length < 0:
            self._request_length = None
            if not (flags & _RF_CONNECTION_CLOSE):
                self._append_header(_CONNECTION, b"close")
            self._request_flags |= _RF_CONNECTION_CLOSE

        if not (flags & _RF_HOST):
            self._append_header(_HOST, self._hostport)

        if not (flags & _RF_ACCEPT_ENCODING):
            self._append_header(_ACCEPT_ENCODING, b"identity")

        if self._request_chunked:
            if not (flags & _RF_TRANSFER_ENCODING):
                self._append_header(_TRANSFER_ENCODING, _CHUNKED)
        else:
            if not (flags & _RF_CONTENT_LENGTH):
                if body is None:
                    if self.method in _METHODS_EXPECTING_BODY:
                        self._request_length = 0
                        self._append_header(_CONTENT_LENGTH, b"0")
                elif isinstance(body, (bytes, bytearray, memoryview)):
                    self._request_length = len(body)
                    self._append_header(_CONTENT_LENGTH, str(len(body)).encode())

        return body

    def send(self, data):
        try:
            if isinstance(data, str):
                data = data.encode()
            self._send_request_body(data)
        except Exception:
            self._abort_attempt()
            raise

    def _send_request_body(self, data):
        send = self._send_chunk if self._request_chunked else self._send_raw

        if data is None:
            return

        if isinstance(data, (bytes, bytearray, memoryview)):
            send(data)
            return

        reader = getattr(data, "readinto", None)
        if callable(reader):
            buf = bytearray(self._blocksize)
            bmv = memoryview(buf)
            while True:
                try:
                    n = reader(buf)
                except OSError as e:
                    _reraise_body_error(e)
                if n is None:
                    continue
                if type(n) is not int or n < 0 or n > self._blocksize:
                    raise RuntimeError("invalid body part")
                if n == 0:
                    return
                if n == self._blocksize:
                    send(buf)
                else:
                    send(bmv[:n])

        reader = getattr(data, "read", None)
        if callable(reader):
            while True:
                try:
                    buf = reader(self._blocksize)
                except OSError as e:
                    _reraise_body_error(e)
                if buf is None:
                    continue
                if isinstance(buf, str):
                    buf = buf.encode()
                if not isinstance(buf, (bytes, bytearray, memoryview)):
                    raise RuntimeError("invalid body part")
                if not buf:
                    return
                send(buf)

        try:
            if isgeneratorfunction(data):
                data = data()
        except OSError as e:
            _reraise_body_error(e)

        try:
            parts = iter(data)
        except TypeError:
            raise RuntimeError("invalid body")

        while True:
            try:
                part = next(parts)
            except StopIteration:
                return
            except OSError as e:
                _reraise_body_error(e)

            if isinstance(part, str):
                part = part.encode()

            if isinstance(part, (bytes, bytearray, memoryview)):
                send(part)
            else:
                raise RuntimeError("invalid body part")

    def _send_raw(self, data, accounting=True):
        if not data:
            return
        sock = self._sock
        if sock is None:
            raise NotConnected()

        try:
            sock.sendall(data)
            if accounting is True:
                self._request_bytes += len(data)
        except OSError as e:
            _reraise_transport_error(e)

    def _send_chunk(self, data, accounting=True):
        if not data:
            return
        self._send_raw(b"%X\r\n" % len(data), False)
        self._send_raw(data, accounting)
        self._send_raw(_CRLF, False)

    def getresponse(self, *, decode_chunked=None, all_headers=False, and_cookies=None):
        if self._sock is None:
            raise NotConnected()

        response_reusable = not (self._request_flags & _RF_CONNECTION_CLOSE)
        resp = None
        try:
            if self._request_chunked:
                self._send_raw(b"0\r\n\r\n", False)
            elif type(self._request_length) is int:
                if self._request_bytes < self._request_length:
                    raise ImproperConnectionState()
                if self._request_bytes > self._request_length:
                    response_reusable = False

            http_version, status, reason = self._read_response_status()
            response_headers = _parse_headers(self._read_head_line, all_headers, and_cookies)

            resp = HTTPResponse(
                self._sock, self.method, self.url,
                http_version, status, reason, response_headers,
                decode_chunked=decode_chunked)
            resp._blocksize = self._blocksize
            resp._reusable = resp._reusable and response_reusable

            if resp._reusable:
                self._resp = resp
                resp._conn = self
                if self._request_head is not None:
                    self._request_head[:] = _EMPTY
            else:
                self._resp = None
                resp._conn = None
                self._sock = None
                self._reset_request()

            if resp._response_length == 0 and resp.status != 101:
                resp.close()

            return resp
        except Exception:
            self._abort_attempt(resp)
            raise
        finally:
            if _GC_FREE_THRESHOLD and gc.mem_free() < _GC_FREE_THRESHOLD:
                gc.collect()

    def _append_header(self, name, value):
        self._request_head.extend(name)
        self._request_head.extend(b": ")
        self._request_head.extend(value)
        self._request_head.extend(_CRLF)

    def _track_request_header(self, name, value):
        len_name = len(name)
        flags = self._request_flags

        if len_name == 4:
            if _equalsci(name, _HOST, 4):
                flags |= _RF_HOST
        elif len_name == 10:
            if _equalsci(name, _CONNECTION, 10):
                flags |= _RF_CONNECTION
                if value is not None and len(value) == 5 and _equalsci(value, b"close", 5):
                    flags |= _RF_CONNECTION_CLOSE
        elif len_name == 14:
            if _equalsci(name, _CONTENT_LENGTH, 14):
                flags |= _RF_CONTENT_LENGTH
                if value is not None:
                    current = self._request_length
                    try:
                        value = int(value, 10)
                    except (TypeError, ValueError):
                        value = -1
                    if value >= 0 and (current is None or current == value):
                        self._request_length = value
                    else:
                        self._request_length = -1
        elif len_name == 15:
            if _equalsci(name, _ACCEPT_ENCODING, 15):
                flags |= _RF_ACCEPT_ENCODING
        elif len_name == 17:
            if _equalsci(name, _TRANSFER_ENCODING, 17):
                flags |= _RF_TRANSFER_ENCODING
                if value is not None:
                    if len(value) == 7 and _equalsci(value, _CHUNKED, 7):
                        flags |= _RF_TRANSFER_CHUNKED

        self._request_flags = flags

    def _call_head_io(self, func, *args):
        loops = 3
        while loops > 0:
            loops -= 1
            try:
                return func(*args)
            except OSError as e:
                err = getattr(e, "errno", None)
                if err == errno.EINTR and loops > 0:
                    continue
                if err == errno.EINTR:
                    raise
                _reraise_transport_error(e)

    def _read_head_line(self):
        return self._call_head_io(self._sock.readline)

    def _read_response_status(self):
        while True:
            first = self._call_head_io(self._sock.read, 1)
            if not first:
                raise RemoteDisconnected()
            if first != b"H":
                raise BadStatusLine()
            line = self._read_head_line()
            if not line or not line.endswith(_LF):
                raise BadStatusLine()

            if not line.startswith(b"TTP/"):
                raise BadStatusLine()

            parts = line.split(None, 2)
            if len(parts) == 3:
                version, status, reason = parts
            elif len(parts) == 2:
                version, status = parts
                reason = _EMPTY
            else:
                raise BadStatusLine()

            if len(status) != 3 or not status.isdigit():
                raise BadStatusLine()
            status = int(status, 10)
            if status == 101 or status >= 200:
                break
            if status < 100:
                raise BadStatusLine()

            while True:
                line = self._read_head_line()
                if line == _CRLF or line == _LF or not line:
                    break
                if not line.endswith(_LF):
                    raise BadStatusLine()

        if version == b"TTP/1.0":
            version = 10
        elif version.startswith(b"TTP/1."):
            version = 11
        else:
            raise UnknownProtocol()

        return version, status, reason

    def _reset_request(self):
        self.method = None
        self.url = None
        self._request_length = None
        self._request_bytes = 0
        self._request_flags = 0
        self._request_chunked = False
        if self._request_head is not None:
            self._request_head[:] = _EMPTY

    def _abort_attempt(self, resp=None):
        if resp is None:
            resp = self._resp
        resp_sock = None
        if resp is not None:
            resp_sock = self._sever_response(resp)
        sock, self._sock = self._sock, None
        _close_quietly(sock)
        if resp_sock is not sock:
            _close_quietly(resp_sock)

    def _sever_response(self, resp):
        sock = resp._sock
        if self._resp is resp:
            self._resp = None
        if resp._conn is self:
            resp._conn = None
        resp._sock = None
        return sock

    def _open_socket(self):
        network = self._network
        if network is not None:
            try:
                ready = network()
            except Exception as e:
                raise NetworkError(str(e))
            if not ready:
                raise NetworkError()
        if _GC_FREE_THRESHOLD and gc.mem_free() < _GC_FREE_THRESHOLD:
            gc.collect()
        try:
            self._sock = create_connection(
                (self._hostaddr, self.port), self.timeout)
        except OSError as e:
            _reraise_transport_error(e)

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
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.verify_mode = ssl.CERT_NONE
            self._context = context

        def _open_socket(self):
            super()._open_socket()
            raw = self._sock
            gc.collect()
            try:
                self._sock = self._context.wrap_socket(raw, server_hostname=self._hostname)
            except Exception as e:
                self._sock = None
                _close_quietly(raw)
                _reraise_transport_error(e)
            finally:
                gc.collect()

