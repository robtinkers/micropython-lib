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
_USE_VIPER = const(1)

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
_CS_RESPONSE_REUSABLE = const(4)

_ACCEPT_ENCODING = b"Accept-Encoding"
_CONNECTION = b"Connection"
_CONTENT_LENGTH = b"Content-Length"
_CONTENT_TYPE = b"Content-Type"
_HOST = b"Host"
_LOCATION = b"Location"
_SET_COOKIE = b"Set-Cookie"
_TRANSFER_ENCODING = b"Transfer-Encoding"

_CHUNKED = b"chunked"
_CLOSE = b"close"
_EMPTY = b""

_KEEP_RESPONSE_HEADERS = {
    8: (_LOCATION,),
    10:(_SET_COOKIE, _CONNECTION),
    12:(_CONTENT_TYPE,),
    14:(_CONTENT_LENGTH,),
    17:(_TRANSFER_ENCODING,),
}

_ENONET = getattr(errno, "ENONET", 64)
_ENETDOWN = getattr(errno, "ENETDOWN", 100)
_ENETUNREACH = getattr(errno, "ENETUNREACH", 101)
_EHOSTDOWN = getattr(errno, "EHOSTDOWN", 112)
_EHOSTUNREACH = getattr(errno, "EHOSTUNREACH", 113)

class HTTPException(Exception): pass

class BadStatusLine(HTTPException): pass

class RemoteDisconnected(BadStatusLine): pass

class UnknownProtocol(BadStatusLine): pass

class IncompleteWrite(HTTPException):
    def __init__(self, value, response_bytes, response_length, error):
        super().__init__(value)
        self.count = response_bytes
        self.length = response_length
        if type(response_bytes) is int and type(response_length) is int:
            self.expected = response_length - response_bytes
        else:
            self.expected = None
        self.error = error

class IncompleteRead(HTTPException):
    def __init__(self, value, response_bytes, response_length, error, status):
        super().__init__(value)
        self.count = response_bytes
        self.length = response_length
        if type(response_bytes) is int and type(response_length) is int:
            self.expected = response_length - response_bytes
        else:
            self.expected = None
        self.error = error
        self.status = status

class ImproperConnectionState(HTTPException): pass

class CannotSendRequest(ImproperConnectionState): pass

class CannotSendHeader(ImproperConnectionState): pass

class ResponseNotReady(ImproperConnectionState): pass

class NotConnected(ImproperConnectionState): pass

class InvalidURL(ValueError): pass

def _encode_and_validate(x, must_return_bytes=False):
    if x is None:
        return None
    if isinstance(x, (str, memoryview)):
        x = bytes(x)
    elif not isinstance(x, (bytes, bytearray)):
        x = str(x).encode()
    if b"\r" in x or b"\n" in x:
        return None
    if not must_return_bytes or type(x) is bytes:
        return x
    return bytes(x)

if _USE_VIPER:

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
        if version.startswith(b"TTP/1."):
            return 11, status, reason
        raise UnknownProtocol(first + version)

    raise BadStatusLine(first + line)

def _parse_headers(sock, status, all_headers, and_cookies):
    if and_cookies is None:
        and_cookies = all_headers

    headers = []
    while True:
        line = sock.readline()
        if not line:
            raise IncompleteRead("connection closed while reading response headers", None, None, None, status)
        if not line.endswith(b"\n"):
            raise IncompleteRead("incomplete response header line", None, None, None, status)
        if line == b"\r\n" or line == b"\n":
            return headers
        if line[0] <= 32:
            continue

        pos = line.find(b":")
        if pos == -1:
            continue

        name = None
        for cand in _KEEP_RESPONSE_HEADERS.get(pos, ()):
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

    if chunked is not None:
        if length is not None and length >= 0:
            return False, length, False
        return False, None, False

    if length == -1:
        return False, None, False

    return False, length, (reusable and length is not None)

class HTTPResponse:
    _chunk_remaining = None

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
        self._bytes = 0

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    @property
    def closed(self):
        return self._sock is None

    def getheaders(self):
        return iter(self._headers)

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

    def read(self, amt=None):
        return self._read_body(None, amt)

    def readinto(self, buf):
        if buf is None:
            raise TypeError("buffer required")
        return self._read_body(buf, None)

    def detach(self):
        sock = self._sock
        if sock is None:
            raise NotConnected()
        owner = self._owner
        if owner is not None:
            owner.release_response(self, None, None)
        self._sock = self._owner = None
        return sock

    def close(self):
        self._release_socket(
            self._bytes == self._length)

    def _abort(self, value):
        self._release_socket(False)
        raise IncompleteRead(value, self._bytes, self._length, None, self.status)

    def _release_socket(self, complete):
        sock = self._sock
        owner = self._owner
        if owner is not None:
            owner.release_response(self, sock, complete)
        self._sock = self._owner = None

    def _append_data(self, out, data):
        if not out:
            return data
        if type(out) is bytes:
            out = bytearray(out)
        out.extend(data)
        return out

    def _chunk_available(self):
        while True:
            if self._chunk_remaining is None:
                line = self._sock.readline()
                if not line:
                    self._abort("chunking error")
                pos = line.find(b";")
                try:
                    if pos >= 0:
                        line = line[:pos]
                    size = int(line, 16)
                    if size < 0:
                        self._abort("negative chunk size")
                except ValueError:
                    self._abort("invalid chunk size")
                if size > 0:
                    self._chunk_remaining = size
                    return size
                while True:
                    line = self._sock.readline()
                    if (line == b"\r\n" or line == b"\n"):
                        self._length = self._bytes
                        self.close()
                        return 0
                    if not line:
                        self._abort("chunking error")
            elif self._chunk_remaining == 0:
                line = self._sock.readline()
                if not line:
                    self._abort("chunking error")
                if not (line == b"\r\n" or line == b"\n"):
                    self._abort("invalid chunk terminator")
                self._chunk_remaining = None
            else:
                return self._chunk_remaining

    def _read_body(self, buf, amt):
        try:
            sock = self._sock
            into = buf is not None
            if sock is None:
                if (self._length is not None and
                        self._bytes >= self._length):
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

            if (self._length is not None):
                remaining = self._length - self._bytes
                if remaining == 0:
                    self.close()
                    return 0 if into else _EMPTY
                if unbounded:
                    amt = remaining
                    unbounded = False
                else:
                    amt = min(amt, remaining)

            if into:
                if self._chunked:
                    bmv = buf if isinstance(buf, memoryview) else memoryview(buf)
                    total = 0
                    while total < amt:
                        want = min(self._chunk_available(), amt - total)
                        if want == 0:
                            break
                        n = sock.readinto(bmv[total:] if total else bmv, want)
                        if not n:
                            self._abort("readinto() empty")
                        self._bytes += n
                        self._chunk_remaining -= n
                        total += n
                    return total

                n = sock.readinto(buf, amt)
                if not n:
                    if (self._length is None):
                        self._length = self._bytes
                        self.close()
                        return 0
                    self._abort("readinto() empty")

                self._bytes += n
                if (self._length is not None) and (self._bytes >= self._length):
                    self.close()
                return n

            if self._chunked:
                out = _EMPTY
                len_out = 0
                while unbounded or len_out < amt:
                    avail = self._chunk_available()
                    if unbounded:
                        want = min(avail, _READ_BLOCK_SIZE)
                    else:
                        want = min(amt - len_out, avail, _READ_BLOCK_SIZE)
                    if want == 0:
                        break
                    chunk = sock.read(want)
                    if not chunk:
                        self._abort("read() empty")
                    len_chunk = len(chunk)
                    self._bytes += len_chunk
                    self._chunk_remaining -= len_chunk
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
                data = sock.read(want)
                if not data:
                    if (self._length is None):
                        self._length = self._bytes
                        self.close()
                        break
                    self._abort("read() failed")
                len_data = len(data)
                self._bytes += len_data
                len_out += len_data
                out = self._append_data(out, data)
                if (self._length is not None) and (self._bytes >= self._length):
                    self.close()
                    break
            if _READ_MUST_RETURN_BYTES and type(out) is not bytes:
                out = bytes(out)
            return out

        except MemoryError:
            self._release_socket(False)
            raise
        except OSError as e:
            count = self._bytes
            length = self._length
            error = e.errno or 0
            status = self.status
            self._release_socket(False)
            raise IncompleteRead(str(e), count, length, error, status)

class HTTPConnection:
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
            the_host = b"[" + the_host + b"]"
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

    def release_response(self, response, sock, complete):
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
        self._state = _CS_REQUEST_STARTED

        try:
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

            self.method = method
            self.url = valid_url

            if self._head is None:
                self._head = bytearray(_REQUEST_HEAD_SIZE)
                self._head[:] = _EMPTY
            self._head.extend(method)
            self._head.extend(b" ")
            self._head.extend(valid_url)
            self._head.extend(b" HTTP/1.1\r\n")

            if skip_host:
                self._flags |= _RF_HOST
            if skip_accept_encoding:
                self._flags |= _RF_ACCEPT_ENCODING
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

        len_name = len(name)
        length = self._length
        flags = self._flags

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

        self._length = length
        self._flags = flags

    def endheaders(self, body=None, *, encode_chunked=None):
        if self._state != _CS_REQUEST_STARTED:
            raise CannotSendHeader()

        try:
            body = self._prep_request(body, encode_chunked)
        except Exception:
            self._reset_request()
            raise

        opening = self._sock is None
        try:
            if opening:
                self._open_socket()
                opening = False
            self._send_bytes(self._head, False)
            self._bytes = 0
            self._send_bytes(b"\r\n", False)
            self._state = _CS_REQUEST_SENT
            self._send_body(body)
        except Exception as e:
            if opening:
                self._abort_request()
                raise
            count = self._bytes
            length = self._length
            error = e.errno or 0 if isinstance(e, OSError) else e.__class__.__name__
            self._abort_request()
            raise IncompleteWrite(str(e), count, length, error)
        finally:
            if _RECYCLE_HEADER_BUFFER:
                self._head[:] = _EMPTY
            else:
                self._head = None

    def send(self, body):
        if self._state != _CS_REQUEST_SENT:
            raise CannotSendRequest()
        if self._sock is None:
            raise NotConnected()

        old_bytes = self._bytes
        try:
            self._send_body(body)
        except Exception as e:
            count = self._bytes
            length = self._length
            error = e.errno or 0 if isinstance(e, OSError) else e.__class__.__name__
            self._abort_request()
            raise IncompleteWrite(str(e), count, length, error)
        return self._bytes - old_bytes

    def getresponse(self, *, all_headers=False, and_cookies=None):
        state = self._state
        if (self._resp is not None or
                (state != _CS_REQUEST_SENT and
                 state != _CS_RECEIVING_RESPONSE)):
            raise ResponseNotReady()
        if self._sock is None:
            raise NotConnected()

        resp = None
        try:
            if state == _CS_REQUEST_SENT:
                self._state = _CS_RECEIVING_RESPONSE
                if self._chunked:
                    try:
                        self._send_bytes(b"0\r\n\r\n", False)
                    except Exception as e:
                        error = e.errno or 0 if isinstance(e, OSError) else e.__class__.__name__
                        raise IncompleteWrite(str(e), self._bytes, self._length, error)
                elif (self._length is not None and
                      self._bytes != self._length):
                    raise ImproperConnectionState(
                        "request body length does not match Content-Length",
                        self._bytes,
                        self._length)

            status = None
            try:
                version, status, reason = _parse_status_line(self._sock)
                response_headers = _parse_headers(self._sock, status, all_headers, and_cookies)
            except OSError as e:
                raise IncompleteRead(str(e), None, None, e.errno or 0, status)

            if _GC_FREE_THRESHOLD and gc.mem_free() < _GC_FREE_THRESHOLD:
                gc.collect()

            response_chunked, response_length, reusable = _derive_response_framing(
                self.method, version, status, response_headers)

            if status < 200 and status != 101:
                sock = owner = None
                if not reusable:
                    self._flags |= _RF_CONNECTION_CLOSE
            else:
                sock = self._sock
                reusable = (
                    reusable and
                    not (self._flags & _RF_CONNECTION_CLOSE)
                )
                owner = self

            resp = HTTPResponse(
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
            body = bytes(body)

        flags = self._flags
        length = self._length

        if encode_chunked is not None:
            chunked = bool(encode_chunked)
        elif flags & _RF_TRANSFER_ENCODING:
            chunked = bool(flags & _RF_TRANSFER_CHUNKED)
        elif flags & _RF_CONTENT_LENGTH:
            chunked = False
        elif isinstance(body, (bytes, bytearray, memoryview)):
            chunked = False
            length = len(body)
        else:
            chunked = body is not None

        self._chunked = chunked

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
        self._length = length

        return body

    def _send_body(self, body):
        send = self._send_chunk if self._chunked else self._send_bytes

        if callable(body):
            body = body()

        if body is None:
            return

        if isinstance(body, str):
            body = bytes(body)

        if isinstance(body, (bytes, bytearray, memoryview)):
            send(body)
            return

        reader = getattr(body, "readinto", None)
        if callable(reader):
            buf = bytearray(_READ_BLOCK_SIZE)
            bmv = memoryview(buf)
            while True:
                n = reader(buf)
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
                buf = reader(_READ_BLOCK_SIZE)
                if buf is None:
                    continue
                if isinstance(buf, str):
                    buf = bytes(buf)
                if not isinstance(buf, (bytes, bytearray, memoryview)):
                    raise TypeError("invalid body part")
                if not buf:
                    return
                send(buf)

        for part in body:
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

        self._sock.sendall(data)
        if accounting:
            self._bytes += len(data)

    def _send_chunk(self, data):
        if not data:
            return
        self._send_bytes(b"%X\r\n" % len(data), False)
        self._send_bytes(data)
        self._send_bytes(b"\r\n", False)

    def _open_socket(self):
        network = self._network
        if network is not None:
            try:
                ready = network()
            except OSError:
                raise
            except Exception as e:
                raise OSError(_ENETDOWN, str(e))
            if not ready:
                raise OSError(_ENETUNREACH, "network unreachable")
        if _GC_FREE_THRESHOLD and gc.mem_free() < _GC_FREE_THRESHOLD:
            gc.collect()
        self._sock = create_connection((self._hostaddr, self.port), self._timeout)

    def _reset_request(self):
        self._state = _CS_IDLE
        self._resp = None
        self.method = None
        self.url = None
        self._length = None
        self._bytes = None
        self._flags = 0
        self._chunked = False
        if _RECYCLE_HEADER_BUFFER and self._head is not None:
            self._head[:] = _EMPTY
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
            except Exception:
                self._sock = None
                _close_quietly(raw)
                raise
            finally:
                gc.collect()
