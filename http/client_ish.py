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
_CHUNKED = b"chunked"

_ACCEPT_ENCODING = b"Accept-Encoding"
_CONNECTION = b"Connection"
_CONTENT_LENGTH = b"Content-Length"
_HOST = b"Host"
_SET_COOKIE = b"Set-Cookie"
_TRANSFER_ENCODING = b"Transfer-Encoding"

_CONNECTION_ERRNOS = (
    errno.ECONNABORTED,
    errno.ECONNREFUSED,
    errno.ECONNRESET,
    getattr(errno, "EPIPE", 32),
    getattr(errno, "ESHUTDOWN", 108),
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

@micropython.viper
def _ip4match(buf:ptr8, length:int) -> int:
    i = 0
    while i < length:
        b = buf[i]
        if not (b == 46 or (48 <= b and b <= 57)):
            return 0
        i += 1
    return 1

def _encode_and_validate(x):
    if x is None:
        return None
    if isinstance(x, str):
        x = x.encode()
    elif not isinstance(x, (bytes, bytearray, memoryview)):
        x = str(x).encode()
    if b"\r" in x or b"\n" in x:
        return None
    return x

def _decode_latin1(buf, default=None):
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

def _normalize_name(buf):
    if isinstance(buf, str):
        buf = buf.encode()
    elif not isinstance(buf, (bytes, bytearray, memoryview)):
        return None
    len_buf = len(buf)
    if _lower_case(buf, 0, len_buf, 0):
        return buf
    out = bytearray(len_buf)
    _lower_case(buf, 0, len_buf, out)
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

        pos = line.find(b":")
        if pos == -1:
            continue

        name = None
        cands = _keep_response_headers.get(pos)
        if cands is not None:
            for cand in cands:
                if _equalsci(line, cand, pos):
                    name = cand
                    break

        if name is None:
            if not all_headers:
                continue
            name = line[:pos]
        elif name == _SET_COOKIE and not and_cookies:
            continue

        start, end = pos + 1, len(line)
        while start < end and line[start] <= 32: start += 1
        while end > start and line[end - 1] <= 32: end -= 1
        headers.append((name, line[start:end]))

def _parse_authority(host, port, default_port):
    if not isinstance(host, str):
        raise TypeError("host must be str")

    rest = ""
    ip4check = False
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
        hostaddr = normalized_host
        ip4check = True

    if rest:
        if rest.isdigit():
            port = int(rest, 10)
        else:
            raise InvalidURL()

    encoded_host = normalized_host.encode()

    if ip4check:
        if encoded_host and _ip4match(encoded_host, len(encoded_host)):
            hostname = None
        else:
            hostname = normalized_host

    if port is None or port == default_port:
        hostport = encoded_host
        port = default_port
    else:
        hostport = b"%s:%d" % (encoded_host, port)

    return normalized_host, hostaddr, hostname, hostport, port

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
        if start <= pos < end:
            end = pos

    pos = url.rfind(b"@", start, end)
    if start <= pos < end:
        start = pos + 1

    return url[start:end]

def _determine_response_framing(method, http_version, status, response_headers):
    http10 = (http_version == 10)
    content_length_value = None
    transfer_encoding_chunked = None
    reusable = None

    for key, val in response_headers:
        len_key = len(key)

        if len_key == 14 and _equalsci(key, _CONTENT_LENGTH, 14):
            try:
                val = int(val, 10)
            except (TypeError, ValueError):
                val = -1

            if val < 0:
                content_length_value = -1
            elif content_length_value is None:
                content_length_value = val
            elif content_length_value != val:
                content_length_value = -1

        elif len_key == 17 and _equalsci(key, _TRANSFER_ENCODING, 17):
            if transfer_encoding_chunked is not False:
                len_val = len(val)
                if len_val == 7:
                    transfer_encoding_chunked = bool(_equalsci(val, _CHUNKED, 7))
                elif len_val > 7:
                    transfer_encoding_chunked = val.endswith(_CHUNKED)

        elif len_key == 10 and _equalsci(key, _CONNECTION, 10):
            if reusable is not False:
                if http10:
                    reusable = (len(val) == 10 and _equalsci(val, b"keep-alive", 10))
                elif len(val) == 5 and _equalsci(val, b"close", 5):
                    reusable = False

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
        return None if (self._response_length is None) else (self._response_length - self._response_bytes)

    @property
    def reason(self):
        return _decode_latin1(self._reason.strip(), "")

    def getheaders(self):
        out = []
        for key, val in self._headers:
            try:
                out.append((_decode_latin1(key),
                            _decode_latin1(val)))
            except UnicodeError:
                pass
        return out

    def iter_rawheaders(self):
        return iter(self._headers)

    def getheader(self, name, default=None):
        return _decode_latin1(self.rawheader(name, None), default)

    def rawheader(self, name, default=None, *, join=b", "):
        name = _normalize_name(name)
        len_name = len(name)
        result = None
        for key, val in self._headers:
            if len(key) != len_name or not _equalsci(key, name, len_name):
                continue
            if result is None:
                result = val
            else:
                result += join + val
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

    def _abort(self, value="aborted"):
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
        try:
            return func(*args)
        except Exception as e:
            self._finish_response(False)
            _reraise_transport_error(e)

    def _get_chunk_left(self):
        while True:
            if self._chunk_left is None:
                line = self._call_body_io(self._sock.readline)
                if not line:
                    self._abort()
                pos = line.find(b";")
                try:
                    if pos >= 0:
                        line = line[:pos]
                    size = int(line, 16)
                    if size < 0:
                        self._abort("negative chunk-size")
                except MemoryError:
                    self._finish_response(False)
                    raise
                except ValueError:
                    self._abort("malformed chunk-size")
                if size > 0:
                    self._chunk_left = size
                    return size
                while True:
                    line = self._call_body_io(self._sock.readline)
                    if (line == _CRLF or line == _LF):
                        self._response_chunked = False
                        self._response_length = self._response_bytes
                        self.close()
                        return 0
                    if not line:
                        self._abort()
            elif self._chunk_left == 0:
                line = self._call_body_io(self._sock.readline)
                if not line:
                    self._abort()
                if not (line == _CRLF or line == _LF):
                    self._abort("malformed terminator")
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
            if (self._response_length is not None) and (self._response_bytes >= self._response_length):
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
                    want = min(self._get_chunk_left(), amt - total)
                    if want == 0:
                        break
                    target = bmv[total:]
                    n = self._call_body_io(sock.readinto, target, want)
                    if not n:
                        self._abort()
                    self._response_bytes += n
                    self._chunk_left -= n
                    total += n
                return total

            n = self._call_body_io(sock.readinto, buf, amt)
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
                avail = self._get_chunk_left()
                if unbounded:
                    want = min(avail, self._blocksize)
                else:
                    want = min(amt - len_out, avail, self._blocksize)
                if want == 0:
                    break
                chunk = self._call_body_io(sock.read, want)
                if not chunk:
                    self._abort()
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
                if (self._response_length is None):
                    self._response_length = self._response_bytes
                    self.close()
                    break
                self._abort()
            len_data = len(data)
            self._response_bytes += len_data
            len_out += len_data
            out = self._append_read_data(out, data)
            if (self._response_length is not None) and (self._response_bytes >= self._response_length):
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

        method = _encode_and_validate(method)
        if not method:
            raise ValueError("bad method")
        if type(method) is not bytes:
            method = bytes(method)
        if not method.isupper():
            method = method.upper()

        if not url:
            url = b"/"
        url = _encode_and_validate(url)
        if url is None:
            raise ValueError("bad url")
        if type(url) is not bytes:
            url = bytes(url)

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

    def putheader(self, name, value):
        name = _encode_and_validate(name)
        if name is None:
            raise ValueError("invalid header name")
        if value is not None:
            value = _encode_and_validate(value)
            if value is None:
                raise ValueError("invalid header value")
            self._append_header(name, value)
        self._track_request_header(name, value)

    def endheaders(self, body=None, *, encode_chunked=None):
        body = self._prep_request(body, encode_chunked)

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
            if body is not None and not isinstance(body, (bytes, bytearray, memoryview)):
                if not (flags & (_RF_CONTENT_LENGTH | _RF_TRANSFER_ENCODING)):
                    self._request_chunked = True
        else:
            self._request_chunked = bool(encode_chunked)

        if (self._request_length is not None) and (self._request_length < 0):
            self._request_length = None
            if not (flags & _RF_CONNECTION_CLOSE):
                self._append_header(_CONNECTION, b"close")
            self._request_flags |= _RF_CONNECTION_CLOSE

        if not (flags & _RF_HOST):
            request_hostport = _parse_hostport_from_url(self.url)
            if request_hostport:
                self._append_header(_HOST, request_hostport)
            elif request_hostport is None:
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
                    self._append_header(_CONTENT_LENGTH, b"%d" % len(body))

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
            if callable(data):
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
            elif (self._request_length is not None):
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
        try:
            return func(*args)
        except OSError as e:
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
