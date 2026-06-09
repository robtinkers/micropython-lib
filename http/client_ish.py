# http/client_ish.py

import micropython, socket, errno, gc

HTTP_PORT = const(80)
HTTPS_PORT = const(443)

# Memory threshold below which GC is called after a request
_GC_THRESHOLD = const(32768)

# HTTP methods that expect a body
_METHODS_EXPECTING_BODY = (b"PATCH", b"POST", b"PUT")

_BLANK = b""
_CRLF = b"\r\n"

class HTTPException(Exception): pass
class NotConnected(HTTPException): pass
class BadStatusLine(HTTPException): pass
class RemoteDisconnected(BadStatusLine): pass
class ImproperConnectionState(HTTPException): pass
class CannotSendRequest(ImproperConnectionState): pass
class CannotSendHeader(ImproperConnectionState): pass
class ResponseNotReady(ImproperConnectionState): pass
class IncompleteRead(HTTPException): pass

@micropython.viper
def _validate_not_c0(buf:ptr8, start:int, end:int, invalid_flags:int) -> int:
    invalid_space = invalid_flags & 1
    i = start
    while i < end:
        b = buf[i]
        if b < 9 or (b == 9 and invalid_space) or (9 < b and b < 32) or (b == 32 and invalid_space):
            return 0
        i += 1
    return 1

def _encode_and_validate(val, invalid_flags):
    if isinstance(val, str):
        val = val.encode() # unfortunately, micropython doesn't support "iso8859-1" encoding
    elif not isinstance(val, (bytes, bytearray, memoryview)):
        val = str(val).encode()
    if not _validate_not_c0(val, 0, len(val), invalid_flags):
        raise ValueError("not ISO-8859-1")
    return val

@micropython.viper
def _lower_case(buf:ptr8, start:int, end:int, dst:ptr8) -> int:
    i = start
    while i < end:
        b = buf[i]
        if dst == 0:
            if 65 <= b and b <= 90:
                return 0
        else:
            if 65 <= b and b <= 90:
                b += 32
            dst[i - start] = b
        i += 1
    return 1

def _normalize_key(buf, start, end):
    assert 0 <= start <= end
    if isinstance(buf, str):
        buf = buf.encode()
    elif not isinstance(buf, (bytes, bytearray, memoryview)):
        buf = str(buf).encode()
    if not _validate_not_c0(buf, start, end, 1):
        raise ValueError("invalid key")
    if _lower_case(buf, start, end, 0):
        if isinstance(buf, memoryview):
            return bytes(buf[start:end])
        if start == 0 and end == len(buf):
            return buf
        return buf[start:end]
    out = bytearray(end - start)
    _lower_case(buf, start, end, out)
    return out

@micropython.viper
def _latin1_to_utf8(buf: ptr8, buflen: int, dst: ptr8) -> int:
    write = int(dst) != 0
    dstlen = 0
    i = 0
    while i < buflen:
        b = buf[i]
        i += 1
        if b < 128:
            if write:
                dst[dstlen] = b
            dstlen += 1
        elif b < 160:
            return -1
        else:
            if write:
                dst[dstlen+0] = 0xC0 | (b >> 6)
                dst[dstlen+1] = 0x80 | (b & 0x3F)
            dstlen += 2
    return dstlen

def decode_latin1(buf):
    buflen = len(buf)
    if buflen == 0:
        return ""
    utf8len = _latin1_to_utf8(buf, buflen, 0)
    if utf8len < 0:
        raise UnicodeError
    if utf8len == buflen:
        return buf.decode()
    utf8dst = bytearray(utf8len)
    _latin1_to_utf8(buf, buflen, utf8dst)
    return utf8dst.decode()

_keep_response_headers = {
    4:[b"etag"],
    8:[b"location"],
    10:[b"connection", b"set-cookie"],
    11:[b"retry-after"],
    12:[b"content-type"],
    14:[b"content-length"],
    16:[b"content-encoding", b"www-authenticate"],
    17:[b"transfer-encoding"],
}

def keep_response_header(key):
    key = _normalize_key(key, 0, len(key))
    if not isinstance(key, bytes):
        key = bytes(key)
    len_key = len(key)
    cands = _keep_response_headers.get(len_key)
    if cands is None:
        _keep_response_headers[len_key] = [key]
    elif key not in cands:
        cands.append(key)

@micropython.viper
def _memeqlc(raw:ptr8, start:int, end:int, cand:ptr8) -> int:
    i = start
    while i < end:
        x = raw[i]
        if 65 <= x and x <= 90:
            x = x + 32
        if x != cand[i - start]:
            return 0
        i += 1
    return 1

def parse_headers(sock, *, all_headers=False, and_cookies=None):
    if and_cookies is None:
        and_cookies = all_headers
    headers = []
    _append = headers.append
    _readline = sock.readline
    while True:
        line = _readline()
        if not line or line == _CRLF or line == b"\n":
            return headers
        # Folded continuations (RFC 7230 deprecated) are dropped.
        if line[0] <= 32:
            continue

        sep = line.find(b":")
        if sep == -1:
            continue

        start, end = 0, sep
        while start < end and line[start] <= 32: start += 1
        while end > start and line[end - 1] <= 32: end -= 1

        key = None
        cands = _keep_response_headers.get(end - start)
        if cands is not None:
            for cand in cands:
                if _memeqlc(line, start, end, cand):
                    key = cand
                    break

        if key is not None:
            if key == b"set-cookie" and not and_cookies:
                continue
        else:
            if not all_headers:
                continue
            key = _normalize_key(line, start, end)
            if not isinstance(key, bytes):
                key = bytes(key)

        start, end = sep + 1, len(line)
        while start < end and line[start] <= 32: start += 1
        while end > start and line[end - 1] <= 32: end -= 1
        _append(key)
        _append(line[start:end])

def create_connection(address, timeout=None):
    host, port = address
    err = None
    for f, t, p, _, a in socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM):
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
        except OSError as e:
            err = e
            if sock is not None:
                try: sock.close()
                except OSError: pass
        except Exception as e:
            if sock is not None:
                try: sock.close()
                except OSError: pass
            raise e
    if err is not None:
        raise err
    raise OSError(errno.EHOSTUNREACH)

def get_hostport(host, port, default_port=0):
    if isinstance(host, str):
        host = host.encode()
    parsed_port = None
    if host.startswith(b"["):
        close = host.rfind(b"]")
        if close == -1:
            raise ValueError("invalid host")
        host, rest = host[1:close], host[close+1:]
        if rest.startswith(b":"):
            if len(rest) > 1:
                parsed_port = rest[1:]
        elif rest:
            raise ValueError("invalid host")
    else:
        sep = host.rfind(b":")
        if sep >= 0:
            host, parsed_port = host[:sep], host[sep+1:]
    if not host:
        raise ValueError("invalid host")
    if port is None:
        port = parsed_port
    if not port:
        port = default_port
    if not isinstance(port, int):
        try:
            port = int(port, 10)
        except ValueError:
            port = -1
    if not (0 <= port <= 65535):
        raise ValueError("invalid port")
    return (host, port)

class HTTPResponse:
    blocksize = 2048

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        return False

    def __init__(self, sock, debuglevel=0, method=None, url=None):
        self._sock = sock
        self.debuglevel = debuglevel
        self._method = method
        self._url = url
        self._headers = None
        self.version = None
        self.status = None
        self.reason = None
        self.chunked = False
        self.chunk_left = None
        self.length = None
        self.will_close = True
        self._bytes_read = 0
        # One-way blocking -> non-blocking transition (see setnonblocking).
        self._nonblocking = False
        # Set by readers on protocol violation or premature EOF; forces
        # the socket closed even if response would otherwise keep-alive.
        self._tainted = False

    def begin(self, *, all_headers=False, and_cookies=None):
        # Framing parse uses readline(), which is blocking-only.
        self._require_blocking()
        self.version, self.status, self.reason = self._read_status()
        if self.debuglevel > 0:
            print("status:", repr(self.version), repr(self.status), repr(self.reason))

        self._headers = parse_headers(self._sock, all_headers=all_headers, and_cookies=and_cookies)
        if self.debuglevel > 0:
            for i in range(0, len(self._headers), 2):
                print("header:", repr(self._headers[i]), "=", repr(self._headers[i+1]))

        # Single pass: pull transfer-encoding, connection, content-length.
        # On duplicate headers the last occurrence wins.
        transfer_encoding = None
        connection = None
        content_length = None
        _headers = self._headers
        for i in range(0, len(_headers), 2):
            k = _headers[i]
            if k == b"transfer-encoding":
                transfer_encoding = _headers[i+1]
            elif k == b"connection":
                connection = _headers[i+1]
            elif k == b"content-length":
                content_length = _headers[i+1]

        self.chunked = bool(transfer_encoding) and b"chunked" in transfer_encoding.lower()
        self.chunk_left = None

        if self.version == 10:
            self.will_close = (not connection) or b"keep-alive" not in connection.lower()
        else:
            self.will_close = bool(connection) and b"close" in connection.lower()

        # Content-Length ignored when chunked.
        self.length = None
        if content_length and not self.chunked:
            try:
                self.length = int(content_length, 10)
                if self.length < 0:
                    self.length = None
            except ValueError:
                pass
        self._bytes_read = 0

        # Responses defined to never have a body.
        if (100 <= self.status < 200
            or self.status == 204 or self.status == 304
            or self._method == b"HEAD"):
            self.chunked = False
            self.length = 0

        # Unknown framing -> body is delimited by close.
        if self.length is None and not self.chunked:
            self.will_close = True

    def _read_status(self):
        while True:
            line = self._sock.readline()
            if self.debuglevel > 0:
                print("status:", repr(line))
            if line == _CRLF or line == b"\n":
                continue
            if not line:
                raise RemoteDisconnected()
            if not line.startswith(b"HTTP/") or not line.endswith(b"\n"):
                raise BadStatusLine()

            line = line.split(None, 2)
            if len(line) == 3:
                version, status, reason = line  # the application should rstrip reason
            elif len(line) == 2:
                version, status = line
                reason = _BLANK
            else:
                raise BadStatusLine()
            try:
                status = int(status, 10)
            except ValueError:
                raise BadStatusLine()

            if not (100 <= status <= 999):
                raise BadStatusLine()

            # 1xx informational (except 101 Switching Protocols) is followed
            # by another status line; drain its headers and re-read.
            if not (100 <= status <= 199) or status == 101:
                break
            while True:
                line = self._sock.readline()
                if line == _CRLF or line == b"\n" or not line:
                    break
                if self.debuglevel > 0:
                    print("header:", repr(line))

        if version == b"HTTP/1.0":
            version = 10
        elif version.startswith(b"HTTP/1."):
            version = 11
        else:
            raise BadStatusLine()

        return version, status, reason

    def close(self, tainted=False):
        if tainted:
            self._tainted = True
        sock = self._sock
        self._sock = None
        if sock is not None:
            framing_incomplete = (
                (self.chunk_left is not None and self.chunk_left != 0)
                or (self.length is not None and self._bytes_read < self.length)
            )
            if self._tainted or framing_incomplete or self.will_close:
                try: sock.close()
                except OSError: pass
        if tainted:
            raise IncompleteRead(self._bytes_read, self.length)

    def isclosed(self):
        return self._sock is None

    def setnonblocking(self):
        if self._sock is not None:
            self._sock.settimeout(0)
        self._nonblocking = True
        self.will_close = True

    def _require_blocking(self):
        if self._nonblocking:
            raise ValueError("operation requires a blocking socket")

    def _require_nonchunked(self):
        if self.chunked:
            raise ValueError("operation requires a non-chunked stream")

    def _next_chunk(self):
        while True:
            if self.chunk_left is None:
                line = self._sock.readline()
                if not line:
                    self.close(True)
                sep = line.find(b";")
                if sep >= 0:
                    line = line[:sep]
                try:
                    size = int(line, 16)
                except ValueError:
                    size = -1
                if size < 0:
                    self.close(True)
                if size > 0:
                    self.chunk_left = size
                    return size
                while True:
                    line = self._sock.readline()
                    if not line or line == _CRLF or line == b"\n":
                        self.close(not line)
                        return 0
            elif self.chunk_left == 0:
                line = self._sock.readline()
                if line != _CRLF and line != b"\n":
                    self.close(True)
                self.chunk_left = None
            else:
                return self.chunk_left

    def read(self, amt=None):
        # Fill-to-completion semantics rely on blocking no-short-reads.
        self._require_blocking()
        if self.isclosed():
            return _BLANK

        unbounded = amt is None or amt < 0
        if unbounded and self.length is None and not self.chunked:
            # Close-delimited: read until EOF in one call.
            try:
                data = self._sock.read()
                if not data:
                    return _BLANK
                self._bytes_read += len(data)
                return data
            finally:
                self.close()

        if self.length is not None:
            remaining = self.length - self._bytes_read
            amt = remaining if unbounded else min(amt, remaining)
            unbounded = False
            if amt == 0:
                if remaining == 0:
                    self.close()
                return _BLANK
        elif not unbounded and amt == 0:
            return _BLANK

        if not self.chunked:
            data = self._sock.read(amt)
            if not data:
                self.close(self.length is not None)
                return _BLANK
            self._bytes_read += len(data)
            if self.length is not None and self._bytes_read >= self.length:
                self.close()
            return data

        out = _BLANK
        len_out = 0
        while unbounded or len_out < amt:
            avail = self._next_chunk()
            want = avail if unbounded else min(amt - len_out, avail)
            if want == 0:
                break
            chunk = self._sock.read(want)
            if not chunk:
                self.close(True)
                break
            len_chunk = len(chunk)
            self._bytes_read += len_chunk
            self.chunk_left -= len_chunk
            len_out += len_chunk
            if out is _BLANK:
                out = chunk
            elif type(out) is bytes:
                out = bytearray(out)
                out.extend(chunk)
            else:
                out.extend(chunk)
        return out

    def readshort(self, amt=None):
        # Single-piece fill relies on blocking no-short-reads.
        self._require_blocking()
        if self.isclosed():
            return _BLANK
        if amt is None or amt < 0:
            amt = self.blocksize
        if self.length is not None:
            remaining = self.length - self._bytes_read
            if remaining == 0:
                self.close()
                return _BLANK
            amt = min(amt, remaining)
        if amt == 0:
            return _BLANK

        if self.chunked:
            amt = min(amt, self._next_chunk())
            if amt == 0:
                return _BLANK

        data = self._sock.read(amt)
        if not data:
            self.close(self.chunked or self.length is not None)
            return _BLANK
        n = len(data)
        self._bytes_read += n
        if self.chunked:
            self.chunk_left -= n
        if self.length is not None and self._bytes_read >= self.length:
            self.close()
        return data

    def readinto(self, buf):
        # Fill-to-completion semantics rely on blocking no-short-reads.
        self._require_blocking()
        if self.isclosed() or not buf:
            return 0

        if not self.chunked:
            if self.length is None:
                amt = len(buf)
            else:
                amt = min(len(buf), self.length - self._bytes_read)
                if amt == 0:
                    self.close()
                    return 0
            n = self._sock.readinto(buf, amt)
            if not n:
                self.close(self.length is not None)
                return 0
            self._bytes_read += n
            if self.length is not None and self._bytes_read >= self.length:
                self.close()
            return n

        buflen = len(buf)
        if isinstance(buf, memoryview):
            bmv = buf
        else:
            bmv = memoryview(buf)

        total = 0
        while total < buflen:
            amt = min(self._next_chunk(), buflen - total)
            if amt == 0:
                break
            if total == 0:
                n = self._sock.readinto(buf, amt)
            else:
                n = self._sock.readinto(bmv[total:], amt)
            if not n:
                self.close(True)
            self._bytes_read += n
            self.chunk_left -= n
            total += n
        return total

    def recv(self, amt=None):
        # Non-chunked only: chunked framing needs blocking readline() parsing
        # which can't survive non-blocking sockets. Use read/readshort instead.
        self._require_nonchunked()
        if self.isclosed():
            return _BLANK
        if amt is None or amt < 0:
            amt = self.blocksize
        if self.length is not None:
            remaining = self.length - self._bytes_read
            if remaining == 0:
                self.close()
                return _BLANK
            amt = min(amt, remaining)
        if amt == 0:
            return _BLANK

        try:
            data = self._sock.recv(amt)
            if data is None:
                return None  # not ready (non-blocking)
        except OSError as e:
            if e.errno == errno.EAGAIN:
                return None  # not ready (non-blocking)
            raise
        if not data:
            self.close(self.length is not None)
            return _BLANK
        n = len(data)
        self._bytes_read += n
        if self.length is not None and self._bytes_read >= self.length:
            self.close()
        return data

    def recvinto(self, buf):
        # Non-chunked only: chunked framing needs blocking readline() parsing
        # which can't survive non-blocking sockets. Use read/readshort instead.
        self._require_nonchunked()
        if self.isclosed() or not buf:
            return 0

        if self.length is None:
            amt = len(buf)
        else:
            amt = min(len(buf), self.length - self._bytes_read)
            if amt == 0:
                self.close()
                return 0

        try:
            n = self._sock.recvinto(buf, amt)
            if n is None:
                return None  # not ready (non-blocking)
        except OSError as e:
            if e.errno == errno.EAGAIN:
                return None  # not ready (non-blocking)
            raise
        if n == 0:
            self.close(self.length is not None)
            return 0
        self._bytes_read += n
        if self.length is not None and self._bytes_read >= self.length:
            self.close()
        return n

    def iter_content(self, blocksize=None):
        buflen = self.blocksize if blocksize is None else blocksize
        buf = bytearray(buflen)
        bmv = memoryview(buf)
        for n in self.iter_content_into(bmv):
            if n == buflen:
                yield bytes(buf)
            else:
                yield bytes(bmv[:n])

    def iter_content_into(self, bmv):
        if not isinstance(bmv, memoryview):
            bmv = memoryview(bmv)
        _readinto = self.readinto
        while True:
            n = _readinto(bmv)
            if n == 0:
                return
            yield n

    def getheaders(self):
        out = []
        for key, val in self.rawheaders():
            try:
                out.append((decode_latin1(key), decode_latin1(val)))
            except UnicodeError:
                pass
        return out

    def rawheaders(self):
        # Returns an iterator
        if self._headers is None:
            raise ResponseNotReady()
        for i in range(0, len(self._headers), 2):
            yield self._headers[i], self._headers[i+1]

    def getheader(self, key, default=None):
        val = self.rawheader(key, None)
        if val is not None:
            try:
                return decode_latin1(val)
            except UnicodeError:
                pass
        return default

    def rawheader(self, key, default=None):
        # Returns first match
        if self._headers is None:
            raise ResponseNotReady()
        key = _normalize_key(key, 0, len(key))
        match = None
        for i in range(0, len(self._headers), 2):
            if self._headers[i] == key:
                if match is None:
                    match = self._headers[i+1]
                else:
                    match = match + b", " + self._headers[i+1]
        return default if match is None else match

    def getcookie(self, name, default=None):
        if isinstance(name, str):
            name = name.encode()
        val = self.rawcookie(name, None)
        if val is not None:
            try:
                return decode_latin1(val)
            except UnicodeError:
                pass
        return default

    def rawcookie(self, name, default=None):
        # Returns first match
        if self._headers is None:
            raise ResponseNotReady()
        len_name = len(name)
        for key, val in self.rawheaders():
            if key != b"set-cookie":
                continue
            if val.startswith(name):
                len_val = len(val)
                if len_val == len_name or val[len_name] == 59:
                    return _BLANK
                if val[len_name] == 61:
                    start = len_name + 1
                    end = val.find(b";", start)
                    if end == -1:
                        end = len_val
                    while start < end and val[start] <= 32: start += 1
                    while end > start and val[end - 1] <= 32: end -= 1
                    if end - start >= 2 and val[start] == 34 and val[end - 1] == 34:
                        start += 1
                        end -= 1
                    return val[start:end]
        return default

class HTTPConnection:
    response_class = HTTPResponse
    default_port = HTTP_PORT
    auto_open = True
    blocksize = 2048
    _merge_buffer_size = 1460

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        return False

    def __init__(self, host, port=None, timeout=None):
        self.debuglevel = 0
        self.timeout = timeout
        self._sock = None
        self._merge_buffer = None
        self._merge_buffmv = None
        self._merged = 0
        self.__response = None
        self._method = None
        self._url = None
        self.host, self.port = get_hostport(host, port, self.default_port)
        self._can_reconnect = False

    def set_debuglevel(self, level):
        self.debuglevel = level

    def connect(self):
        self._sock = create_connection((self.host, self.port), self.timeout)

    def close(self):
        # Suppress the response's own close logic by nulling its socket
        # reference; this object owns the socket teardown.
        self._can_reconnect = False
        self._merged = 0
        self._merge_buffmv = None
        self._merge_buffer = None
        response = self.__response
        self.__response = None
        if response is not None:
            response._sock = None
        sock = self._sock
        self._sock = None
        if sock is not None:
            try: sock.close()
            except OSError: pass

    def request(self, method, url, body=None, headers=None, *, encode_chunked=None):
        have_accept_encoding = False
        have_content_length = False
        have_host = False
        have_transfer_encoding = False

        pairs = None
        if headers is not None:
            if isinstance(headers, dict):
                pairs = list(headers.items())
            elif isinstance(headers, (list, tuple)):
                pairs = headers
            else:
                pairs = list(headers)
            headers = None
            for key, _value in pairs:
                key = _normalize_key(key, 0, len(key))
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
            body = body.encode()

        if encode_chunked is None:
            if body is None:
                encode_chunked = False
                if not have_content_length and self._method in _METHODS_EXPECTING_BODY:
                    self.putheader(b"Content-Length", b"0")
            elif isinstance(body, (bytes, bytearray, memoryview)):
                encode_chunked = False
                if not have_content_length:
                    self.putheader(b"Content-Length", b"%d" % len(body))
            else:
                encode_chunked = not have_content_length
        if encode_chunked and not have_transfer_encoding:
            self.putheader(b"Transfer-Encoding", b"chunked")

        if pairs is not None:
            for key, value in pairs:
                self.putheader(key, value)

        self.endheaders(body, encode_chunked=encode_chunked)

    def putrequest(self, method, url, skip_host=False, skip_accept_encoding=False):
        if self.__response is not None and not self.__response.isclosed():
            raise CannotSendRequest()
        self.__response = None

        self._can_reconnect = self.auto_open
        self._merged = 0

        method = _encode_and_validate(method, 1)
        if not isinstance(method, bytes):
            method = bytes(method)
        if method != b"GET":
            method = method.upper()

        url = _encode_and_validate(url, 1)
        if not isinstance(url, bytes):
            url = bytes(url)

        self._method = method
        self._url = url
        self._putheaderparts(False, method, b" ", url, b" HTTP/1.1\r\n")

        if not skip_host:
            host = self.host
            if b":" in host and not host.startswith(b"["):
                host = b"[" + host + b"]"
            if self.port == self.default_port:
                self.putheader(b"Host", host)
            else:
                self.putheader(b"Host", b"%s:%d" % (host, self.port))
        if not skip_accept_encoding:
            self._putheaderparts(False, b"Accept-Encoding: identity\r\n")

    def putheader(self, key, val):
        if self.__response is not None:
            raise CannotSendHeader()
        if isinstance(key, str):
            key = key.encode()
        val = _encode_and_validate(val, 0)
        self._putheaderparts(False, key, b": ", val, _CRLF)

    def putcookie(self, name, value):
        if self.__response is not None:
            raise CannotSendHeader()
        if isinstance(name, str):
            name = name.encode()
        if isinstance(value, str):
            value = value.encode()
        if not value:
            self._putheaderparts(False, b"Cookie: ", name, b'=', _CRLF)
        elif value.find(b'"') >= 0:
            self._putheaderparts(False, b"Cookie: ", name, b'=', value, _CRLF)
        else:
            self._putheaderparts(False, b"Cookie: ", name, b'="', value, '"', _CRLF)

    def _putheaderparts(self, flush, *parts):
        # Coalesces small writes into a single sendall.
        _send_raw = self._send_raw
        _buffer_size = self._merge_buffer_size
        if self._merge_buffer is None and _buffer_size:
            self._merge_buffer = bytearray(_buffer_size)
            self._merge_buffmv = memoryview(self._merge_buffer)
        _buffer = self._merge_buffer
        _buffmv = self._merge_buffmv
        _merged = self._merged
        for part in parts:
            if _buffmv is None:
                _send_raw(part)
                continue
            len_part = len(part)
            if len_part >= _buffer_size:
                if _merged:
                    _send_raw(_buffmv[:_merged])
                    _merged = 0
                _send_raw(part)
            elif _merged + len_part <= _buffer_size:
                _buffer[_merged:_merged+len_part] = part
                _merged += len_part
            else:
                _send_raw(_buffmv[:_merged])
                _buffer[:len_part] = part
                _merged = len_part
        if flush and _merged:
            _send_raw(_buffmv[:_merged])
            _merged = 0
        self._merged = _merged

    def endheaders(self, message_body=None, *, encode_chunked=False):
        if self.__response is not None:
            raise CannotSendHeader()
        # The flush below sends _CRLF, which clears _can_reconnect via _send_raw.
        self._putheaderparts(True, _CRLF)
        if message_body is not None or encode_chunked:
            self.send(message_body, encode_chunked=encode_chunked)

    def _send_raw(self, data):
        if not data:
            return
        if self.debuglevel > 0:
            print("send:", len(data), "bytes")
        # On the first send of a request, transparently (re)connect if a
        # kept-alive socket has died. Subsequent sends require an open socket.
        if self._can_reconnect:
            if self._sock is not None:
                try:
                    self._sock.sendall(data)
                    self._can_reconnect = False
                    return
                except OSError:
                    try: self._sock.close()
                    except OSError: pass
                self._sock = None
            try:
                self.connect()
            except OSError as e:
                raise NotConnected(str(e))
            self._sock.sendall(data)
            self._can_reconnect = False
            return

        if self._sock is None:
            raise NotConnected("socket missing")
        self._sock.sendall(data)
        self._can_reconnect = False

    def _send_chunk(self, data):
        if data is None:
            if self.debuglevel > 0:
                print("send: terminating chunk")
            self._send_raw(b"0\r\n\r\n")
            return
        if not data:
            return
        len_data = len(data)
        header = b"%X\r\n" % len_data
        if self._merge_buffer is not None and self._merged == 0:
            len_header = len(header)
            total_len = len_header + len_data + 2
            if total_len <= self._merge_buffer_size:
                self._merge_buffer[:len_header] = header
                self._merge_buffer[len_header:len_header+len_data] = data
                self._merge_buffer[len_header+len_data:total_len] = _CRLF
                self._send_raw(self._merge_buffmv[:total_len])
                return
        self._send_raw(header)
        self._send_raw(data)
        self._send_raw(_CRLF)

    # encode_chunked and final_chunk are extensions beyond CPython.
    def send(self, data, *, encode_chunked=False, final_chunk=True):
        send = self._send_chunk if encode_chunked else self._send_raw

        if isinstance(data, str):
            data = data.encode()

        if self.debuglevel > 0:
            print("send:", type(data).__name__)

        if data is None:
            pass

        elif isinstance(data, (bytes, bytearray, memoryview)):
            send(data)

        elif hasattr(data, "readinto"):
            buflen = self.blocksize
            buf = bytearray(buflen)
            bmv = memoryview(buf)
            while True:
                n = data.readinto(buf)
                if not n:
                    break
                if n == buflen:
                    send(buf)
                else:
                    send(bmv[:n])

        else:
            for d in data:
                if isinstance(d, str):
                    d = d.encode()
                if d is not None:
                    send(d)

        if encode_chunked and final_chunk:
            if self.debuglevel > 0:
                print("send: terminator")
            self._send_chunk(None)

    def getresponse(self, **kwargs):
        if self.__response is not None and not self.__response.isclosed():
            raise ResponseNotReady()
        self.__response = None
        response = None
        try:
            response = self.response_class(self._sock, self.debuglevel, self._method, self._url)
            response.begin(**kwargs)
            if response.will_close:
                # Response owns the socket from here.
                self._sock = None
            else:
                self.__response = response
            return response
        except Exception:
            sock = self._sock
            self._sock = None
            if response is not None:
                response.close()
            if sock is not None:
                try: sock.close()
                except OSError: pass
            raise
        finally:
            if _GC_THRESHOLD and gc.mem_free() < _GC_THRESHOLD:
                gc.collect()

    def detach(self):
        if self.__response is not None:
            sock = self.__response._sock
            self.__response._sock = None
            self.__response = None
        else:
            sock = self._sock
        self._sock = None
        self._can_reconnect = False
        self._merged = 0
        self._merge_buffmv = None
        self._merge_buffer = None
        return sock

try:
    import ssl
except ImportError:
    pass
else:
    class HTTPSConnection(HTTPConnection):
        default_port = HTTPS_PORT
        blocksize = 2048
        _merge_buffer_size = 1024

        def __init__(self, *args, context=None, **kwargs):
            super().__init__(*args, **kwargs)
            if context is None:
                # Verification is OFF by default for embedded use.
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.verify_mode = ssl.CERT_NONE
            self._context = context

        def connect(self):
            super().connect()
            gc.collect()
            # SNI is omitted for IP literals (RFC 6066).
            omit_sni = b":" in self.host or all(48 <= c <= 57 or c == 46 for c in self.host)
            raw = self._sock
            try:
                self._sock = self._context.wrap_socket(raw, server_hostname=None if omit_sni else self.host)
            except Exception as e:
                self._sock = None
                if raw is not None:
                    try: raw.close()
                    except OSError: pass
                if isinstance(e, OSError):
                    raise e
                elif isinstance(e, MemoryError):
                    raise OSError(errno.ENOMEM)
                else:
                    raise OSError(errno.EIO)
