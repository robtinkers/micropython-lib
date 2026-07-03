# http/client_ish.py
#
# http.client for Micropython, optimised for memory footprint and churn.
# Extensions include chunking, cookies, non-blocking I/O and more.

import micropython, socket, errno, gc

HTTP_PORT = const(80)
HTTPS_PORT = const(443)

_DEBUG = const(0)
_DEFAULT_TIMEOUT = const(10)
_METHODS_EXPECTING_BODY = (b"PATCH", b"POST", b"PUT")
# gc.collect() after a response when free memory is below this many bytes; 0 disables.
_GC_THRESHOLD = const(32768)

_CS_IDLE     = const(0)  # no request in progress; socket may be closed or idle
_CS_HEADERS  = const(1)  # request line sent; request headers are still open
_CS_BODY     = const(2)  # headers ended; body may be sent; response may be read
_CS_CHUNKING = const(3)  # manual chunked body started; final zero chunk not sent
_CS_RESPONSE = const(4)  # response is active and owns the reusable connection

_MISSING = object()
_SET_COOKIE = b"set-cookie"
_BLANK = b""
_CRLF = b"\r\n"
_LF = b"\n"

# errno sets, resolved at import; a name missing on a minimal port becomes an unmatchable -1.
_WOULDBLOCK_ERRS = (
    errno.EAGAIN,
    errno.EALREADY,
    errno.EINPROGRESS,
    errno.ETIMEDOUT,
    getattr(errno, "EWOULDBLOCK", -1),
)

_CONNECTION_ERRS = (
    errno.EBADF,
    errno.ECONNABORTED,
    errno.ECONNREFUSED,
    errno.ECONNRESET,
    errno.EHOSTUNREACH,
    errno.ENOBUFS,
    errno.ENOTCONN,
    getattr(errno, "EADDRNOTAVAIL", -1),
    getattr(errno, "EHOSTDOWN", -1),
    getattr(errno, "ENETDOWN", -1),
    getattr(errno, "ENETRESET", -1),
    getattr(errno, "ENETUNREACH", -1),
    getattr(errno, "EPIPE", -1),
    getattr(errno, "ESHUTDOWN", -1),
)

# Exception hierarchy mirroring CPython's http.client:
class HTTPException(Exception): pass
class NotConnected(HTTPException): pass
class InvalidURL(HTTPException): pass
# class InvalidURL(HTTPException): pass
# class UnknownProtocol(HTTPException): pass
# class UnknownTransferEncoding(HTTPException): pass
# class UnimplementedFileMode(HTTPException): pass
class IncompleteRead(HTTPException):
#    def __init__(self, *args):
#        super().__init__(*args)
#        # CPython compatibility...
#        self.partial = _BLANK
#        if len(args) > 1 and args[0] is not None and args[1] is not None:
#            self.expected = args[1] - args[0]
#        else:
#            self.expected = None
        pass
class ImproperConnectionState(HTTPException): pass
class CannotSendRequest(ImproperConnectionState): pass
class CannotSendHeader(ImproperConnectionState): pass
class ResponseNotReady(ImproperConnectionState): pass
class BadStatusLine(HTTPException):
#    def __init__(self, *args):
#        super().__init__(*args)
#        # CPython compatibility...
#        self.args = line
#        self.line = line
        pass
# class LineTooLong(HTTPException): pass
class RemoteDisconnected(BadStatusLine): pass
# Custom exceptions:
# class InvalidHeader(HTTPException): pass # TODO: use this for bad client headers/combos
class TimeoutError(NotConnected, OSError): pass

# Viper: 1 if buf[start:end] passes the char class selected by flags.
@micropython.viper
def _validate(buf:ptr8, start:int, end:int, flags:int) -> int:
    invalid_space  = bool(flags & 1)
    invalid_tab    = bool(flags & 2)
    invalid_cookie = bool(flags & 4) # reject '"' ';' '\\'
    invalid_comma  = bool(flags & 8)
    invalid_colon  = bool(flags & 16)
    invalid_equals = bool(flags & 32)
    check_ip4addr  = bool(flags & 256)
    i = start
    while i < end:
        b = buf[i]
        if check_ip4addr:
            if not(b == 46 or (48 <= b and b <= 57)):
                return 0
        elif b == 9:
            if invalid_tab:
                return 0
        elif b < 32:
            return 0
        elif b == 32:
            if invalid_space:
                return 0
        elif b == 34 or b == 59 or b == 92:
            if invalid_cookie:
                return 0
        elif b == 44:
            if invalid_comma:
                return 0
        elif b == 58:
            if invalid_colon:
                return 0
        elif b == 61:
            if invalid_equals:
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

# Validated, lower-cased header name; returns the input uncopied when already conforming.
def _normalize_header_name(buf, start=0, end=None, lower=True):
    if isinstance(buf, str):
        buf = buf.encode()
    elif not isinstance(buf, (bytes, bytearray, memoryview)):
        return None
    if end is None:
        end = len(buf)
    if not _validate(buf, start, end, 19):
        return None
    if not lower or _lower_case(buf, start, end, 0):
        if start == 0 and end == len(buf):
            return buf
        return buf[start:end]
    out = bytearray(end - start)
    _lower_case(buf, start, end, out)
    return out

# Viper: transcode Latin-1 to UTF-8; out==0 sizes only, -1 on 0x80-0x9F (C1 controls).
@micropython.viper
def _latin1_to_utf8(buf: ptr8, len_buf: int, out: ptr8) -> int:
    write = int(out) != 0
    len_out = 0
    i = 0
    while i < len_buf:
        b = buf[i]
        i += 1
        if b < 128:
            if write:
                out[len_out] = b
            len_out += 1
        elif b < 160:
            return -1
        else:
            if write:
                out[len_out+0] = 0xC0 | (b >> 6)
                out[len_out+1] = 0x80 | (b & 0x3F)
            len_out += 2
    return len_out

def decode_latin1(buf, default=_MISSING):
    if buf is None:
        if default is _MISSING:
            raise UnicodeError()
        return default
    len_buf = len(buf)
    if len_buf == 0:
        return ""
    utf8len = _latin1_to_utf8(buf, len_buf, 0)
    if utf8len == len_buf:
        try:
            return buf.decode()
        except UnicodeError:
            utf8len = -1
    if utf8len < 0:
        if default is _MISSING:
            raise UnicodeError()
        return default
    utf8out = bytearray(utf8len)
    _latin1_to_utf8(buf, len_buf, utf8out)
    return utf8out.decode()

# Headers retained by default when all_headers=False, bucketed by name length for cheap lookup.
_keep_response_headers = {
    4:[b"etag"],
    8:[b"location"],
    10:[b"connection", _SET_COOKIE],
    11:[b"retry-after"],
    12:[b"content-type"],
    14:[b"content-length"],
    16:[b"content-encoding", b"www-authenticate"],
    17:[b"transfer-encoding"],
}

def keep_response_header(name):
    name = _normalize_header_name(name)
    if name is None:
        raise ValueError("bad header name")
    if not isinstance(name, bytes):
        name = bytes(name)
    len_name = len(name)
    cands = _keep_response_headers.get(len_name)
    if cands is None:
        _keep_response_headers[len_name] = [name]
    elif name not in cands:
        cands.append(name)

# Viper: case-insensitive substring search; needle must already be lower-case.
@micropython.viper
def _containslc(haystack:ptr8, haystacklen:int, needle:ptr8, needlelen:int) -> int:
    if needlelen == 0:
        return 1
    if needlelen > haystacklen:
        return 0
    last = haystacklen - needlelen
    i = 0
    while i <= last:
        j = 0
        while j < needlelen:
            x = haystack[i + j]
            if 65 <= x and x <= 90:
                x = x + 32
            if x != needle[j]:
                break
            j += 1
        if j == needlelen:
            return 1
        i += 1
    return 0

# Parse headers into a flat [name, value, ...] list. sock may be a readline callable or a socket.
def parse_headers(sock, *, all_headers=False, and_cookies=None):
    if and_cookies is None:
        and_cookies = all_headers
    headers = []
    while True:
        # Accept either a bound readline (routes reads through the response's error handling) or a socket.
        if callable(sock):
            line = sock()
        else:
            line = sock.readline()

        if line == _CRLF or line == _LF:
            return headers

        if not line or not line.endswith(_LF):
            raise RemoteDisconnected()

        # Ignore obsolete line folding (continuation lines).
        if line[0] <= 32:
            continue

        sep = line.find(b":")
        if sep == -1:
            continue

        end = sep
        while end > 0 and line[end - 1] <= 32: end -= 1

        name = None
        cands = _keep_response_headers.get(end)
        if cands is not None:
            for cand in cands:
                if len(cand) == end and _containslc(line, end, cand, end):
                    name = cand
                    break

        if name is None:
            if not all_headers:
                continue
            name = _normalize_header_name(line, 0, end)
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

# socket.create_connection() work-alike: try each resolved address until one connects.
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
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            except (AttributeError, OSError):
                pass
            sock.connect(a)
            return sock
        except OSError as e:
            err = e
            try: sock.close()
            except (AttributeError, OSError): pass
        except Exception:
            try: sock.close()
            except (AttributeError, OSError): pass
            raise
    if err is not None:
        raise err
    raise OSError(errno.EHOSTUNREACH)

class HTTPResponse:
    blocksize = 2048

    def __init__(self, sock, method=None, url=None):
        self._sock = sock
        self._conn = None
        self._headers = None

        self.method = method
        self.url = url
        self.version = None
        self.status = None
        self._reason = None

        self._chunked = False
        self._chunk_left = None
        self._length = None
        self._will_close = True
        self._bytes_read = 0

        self._blocking = True
        self._have_recv_into = hasattr(sock, "recv_into")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        return False

    def _release_conn(self, discard):
        conn, self._conn = self._conn, None
        if conn is not None:
            conn._resp = None
            conn.method = None
            conn.url = None
            conn._state = _CS_IDLE
            if discard:
                conn._sock = None

    # Detach the parent conn and drop our socket. discard=False hands a drained keep-alive socket
    def _teardown(self, discard):
        sock, self._sock = self._sock, None
        self._release_conn(discard)
        if sock is not None and discard:
            try: sock.close()
            except OSError: pass

    # Keep the socket (for reuse) only if the body was fully consumed and framing allows it.
    def close(self):
        discard = (self._will_close or self._chunked or self.status == 101
                or (self._length is not None and self._bytes_read < self._length))
        self._teardown(discard)

    def abort(self):
        self._teardown(True)
        raise IncompleteRead(self._bytes_read, self._length)

    @property
    def closed(self):
        return self._sock is None

    @property
    def chunked(self):
        return self._chunked

    @property
    def length(self):
        return None if self._length is None else self._length - self._bytes_read

    @property
    def reason(self):
        if self._reason is None:
            return None
        return decode_latin1(self._reason.strip(), "")

    def fileno(self):
        if self._sock is None:
            return None
        return self._sock.fileno()

    def begin(self, *, all_headers=False, and_cookies=None):
        if self._headers is not None:
            return
        self._require_blocking()
        self.version, self.status, self._reason = self._read_status()
        if _DEBUG:
            print("status:", repr(self.version), repr(self.status), repr(self.reason))

        self._headers = parse_headers(self._readline, all_headers=all_headers, and_cookies=and_cookies)
        if _DEBUG:
            for i in range(0, len(self._headers), 2):
                print("header:", repr(self._headers[i]), "=", repr(self._headers[i+1]))

        transfer_encoding = None
        connection = None
        content_length = None
        for i in range(0, len(self._headers), 2):
            k = self._headers[i]
            if k == b"transfer-encoding":
                transfer_encoding = self._headers[i+1]
            elif k == b"connection":
                connection = self._headers[i+1]
            elif k == b"content-length":
                content_length = self._headers[i+1]

        self._chunked = bool(transfer_encoding) and bool(_containslc(transfer_encoding, len(transfer_encoding), b"chunked", 7))
        self._chunk_left = None

        if self.version == 10:
            self._will_close = (not connection) or not bool(_containslc(connection, len(connection), b"keep-alive", 10))
        else:
            self._will_close = bool(connection) and bool(_containslc(connection, len(connection), b"close", 5))

        self._length = None
        if content_length and not self._chunked:
            try:
                self._length = int(content_length, 10)
                if self._length < 0:
                    self._length = None
            except ValueError:
                pass
        self._bytes_read = 0

        if (100 <= self.status < 200
            or self.status == 204 or self.status == 304
            or self.method == b"HEAD"):
            self._chunked = False
            self._length = 0

        if self._length is None and not self._chunked:
            self._will_close = True

    def getheaders(self):
        out = []
        for name, value in self.rawheaders():
            try:
                out.append((decode_latin1(name), decode_latin1(value)))
            except UnicodeError:
                pass
        return out

    def rawheaders(self):
        if self._headers is None:
            raise ResponseNotReady()
        for i in range(0, len(self._headers), 2):
            yield self._headers[i], self._headers[i+1]

    def rawheader(self, name, default=None):
        if self._headers is None:
            raise ResponseNotReady()
        if isinstance(name, str):
            name = name.encode()
        len_name = len(name)
        match = None
        for i in range(0, len(self._headers), 2):
            key = self._headers[i]
            if len(key) == len_name and _containslc(name, len_name, key, len_name):
                if match is None:
                    match = self._headers[i+1]
                else:
                    match = match + b", " + self._headers[i+1]
        return default if match is None else match

    def getheader(self, name, default=None):
        return decode_latin1(self.rawheader(name, None), default)

    def rawcookie(self, name, default=None):
        if isinstance(name, str):
            name = name.encode()
        len_name = len(name)
        for key, val in self.rawheaders():
            if key != _SET_COOKIE:
                continue
            if val.startswith(name):
                len_val = len(val)
                if len_val == len_name:
                    return default
                if val[len_name] == 61:  # '='
                    return val[len_name+1:]
        return default

    def getcookie(self, name, default=None):
        rawvalue = self.rawcookie(name, None)
        if rawvalue is None:
            return default
        start, end = 0, rawvalue.find(b";")
        if end == -1:
            end = len(rawvalue)
        while start < end and rawvalue[start] <= 32: start += 1
        while end > start and rawvalue[end - 1] <= 32: end -= 1
        if end - start >= 2 and rawvalue[start] == 34 and rawvalue[end - 1] == 34:
            start += 1
            end -= 1
        return decode_latin1(rawvalue[start:end], default)

    def _read_wrapper(self, resumable, func, *args):
        while True:
            try:
                return func(*args)
            except OSError as e:
                err = e.errno
                if err == errno.EINTR:
                    continue
                if resumable and err in _WOULDBLOCK_ERRS and err != errno.ETIMEDOUT:
                    raise
                self._teardown(True)
                if err == errno.ETIMEDOUT:
                    raise TimeoutError()
                if err in _CONNECTION_ERRS:
                    raise NotConnected("connection lost")
                raise

    def _readline(self):
        if self._sock is None:
            return None
        return self._read_wrapper(False, self._sock.readline)

    def read(self, amt=None):
        return self._read_impl(None, amt)

    def readshort(self, amt=None):
        return self._read_impl(None, amt, short=True)

    def readinto(self, buf):
        if buf is None:
            raise TypeError("buffer required")
        return self._read_impl(buf, None)

    def recv(self, amt=None):
        return self._read_impl(None, amt, non_blocking=True)

    def recv_into(self, buf):
        if buf is None:
            raise TypeError("buffer required")
        return self._read_impl(buf, None, non_blocking=True)

    # Unified body reader for read/readinto/recv/recv_into across all three framing modes.
    def _read_impl(self, buf, amt, short=False, non_blocking=False):
        if self._headers is None:
            raise ResponseNotReady()
        if non_blocking:
            self._require_nonchunked()
        else:
            self._require_blocking()

        into = buf is not None
        if self._sock is None:
            return 0 if into else _BLANK
        if into and not buf:
            return 0
        sock = self._sock

        if into:
            amt = len(buf) if (amt is None or amt < 0) else min(amt, len(buf))
            unbounded = False
        else:
            unbounded = amt is None or amt < 0
            if short and unbounded:
                amt = self.blocksize
                unbounded = False
            elif non_blocking and unbounded:
                amt = self.blocksize
                unbounded = False

        if self._length is not None:
            remaining = self._length - self._bytes_read
            if remaining == 0:
                self.close()
                return 0 if into else _BLANK
            if not unbounded:
                amt = min(amt, remaining)
            else:
                amt = remaining
                unbounded = False
        elif not unbounded and amt == 0:
            return 0 if into else _BLANK

        if non_blocking:
            try:
                if into:
                    if self._have_recv_into:
                        n = sock.recv_into(buf, amt)
                    else:
                        n = sock.readinto(buf, amt)
                    data = None
                else:
                    data = sock.recv(amt)
                    n = None if data is None else len(data)
            except OSError as e:
                err = e.errno
                if err == errno.EINTR or err in _WOULDBLOCK_ERRS:
                    return None
                self._teardown(True)
                if err in _CONNECTION_ERRS:
                    raise NotConnected("connection lost")
                raise

            if n is None:
                return None

            if n == 0:
                if self._length is not None:
                    self.abort()
                self.close()
                return 0 if into else _BLANK

            self._bytes_read += n
            if self._length is not None and self._bytes_read >= self._length:
                self.close()
            return n if into else data

        # Read-to-EOF: no Content-Length and not chunked, so the body ends when the server closes.
        if unbounded and self._length is None and not self._chunked:
            out = _BLANK
            while True:
                data = self._read_wrapper(False, sock.read, self.blocksize)
                if not data:
                    self.close()
                    return out
                self._bytes_read += len(data)
                if out is _BLANK:
                    out = data
                elif type(out) is bytes:
                    out = bytearray(out)
                    out.extend(data)
                else:
                    out.extend(data)

        if short or not self._chunked:
            if short and self._chunked:
                amt = min(amt, self._next_chunk())
                if amt == 0:
                    return 0 if into else _BLANK

            if into:
                n = self._read_wrapper(True, sock.readinto, buf, amt)
                data = None
            else:
                data = self._read_wrapper(True, sock.read, amt)
                n = len(data) if data else 0

            if not n:
                if self._length is not None or self._chunked:
                    self.abort()
                self.close()
                return 0 if into else _BLANK

            self._bytes_read += n
            if self._chunked:
                self._chunk_left -= n
            elif self._length is not None and self._bytes_read >= self._length:
                self.close()
            return n if into else data

        if into:
            bmv = buf if isinstance(buf, memoryview) else memoryview(buf)
            total = 0
            while total < amt:
                want = min(self._next_chunk(), amt - total)
                if want == 0:
                    break
                n = self._read_wrapper(False, sock.readinto, bmv[total:], want)
                if not n:
                    self.abort()
                self._bytes_read += n
                self._chunk_left -= n
                total += n
            return total

        out = _BLANK
        len_out = 0
        while unbounded or len_out < amt:
            avail = self._next_chunk()
            want = avail if unbounded else min(amt - len_out, avail)
            if want == 0:
                break
            chunk = self._read_wrapper(False, sock.read, want)
            if not chunk:
                self.abort()
            len_chunk = len(chunk)
            self._bytes_read += len_chunk
            self._chunk_left -= len_chunk
            len_out += len_chunk
            if out is _BLANK:
                out = chunk
            elif type(out) is bytes:
                out = bytearray(out)
                out.extend(chunk)
            else:
                out.extend(chunk)
        return out

    def iter_content(self, blocksize=None):
        len_buf = self.blocksize if blocksize is None else blocksize
        buf = bytearray(len_buf)
        bmv = memoryview(buf)
        for n in self.iter_content_into(bmv):
            if n == len_buf:
                yield bytes(buf)
            else:
                yield bytes(bmv[:n])

    def iter_content_into(self, bmv):
        if not isinstance(bmv, memoryview):
            bmv = memoryview(bmv)
        while True:
            n = self.readinto(bmv)
            if n == 0:
                return
            yield n

    # One-way switch to non-blocking. Releases the conn (no reuse) but keeps the socket live.
    def setblocking(self, flag):
        if self._headers is None:
            raise ResponseNotReady()
        if self._sock is None:
            raise NotConnected("socket missing")
        if flag:
            raise ValueError("can only transition to non-blocking")
        self._require_nonchunked()
        sock = self._sock
        if sock is not None:
            sock.setblocking(False)
        self._release_conn(True)
        self._blocking = False
        self._will_close = True

    def as_async_stream(self):
        if self._sock is None:
            return None
        import asyncio
        self.setblocking(False)
        return asyncio.StreamReader(self._sock)

    def _require_blocking(self):
        if not self._blocking:
            raise ValueError("operation requires a blocking socket")

    def _require_nonchunked(self):
        if self._chunked:
            raise ValueError("operation requires a non-chunked stream")

    # Read the status line, transparently skipping 1xx interim responses except 101 (upgrade).
    def _read_status(self):
        while True:
            line = self._readline()
            if _DEBUG:
                print("status:", repr(line))
            if line == _CRLF or line == _LF:
                continue
            if not line or not line.endswith(_LF):
                raise RemoteDisconnected()
            if not line.startswith(b"HTTP/"):
                raise BadStatusLine()

            line = line.split(None, 2)
            if len(line) == 3:
                version, status, reason = line
                reason = reason.rstrip()
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

            if not (100 <= status <= 199) or status == 101:
                break
            while True:
                line = self._readline()
                if line == _CRLF or line == _LF or not line:
                    break
                if _DEBUG:
                    print("header:", repr(line))
                if not line.endswith(_LF):
                    raise BadStatusLine()

        if version == b"HTTP/1.0":
            version = 10
        elif version.startswith(b"HTTP/1."):
            version = 11
        else:
            raise BadStatusLine()

        return version, status, reason

    # Advance chunked framing; returns bytes left in the current chunk, 0 at end of body.
    def _next_chunk(self):
        while True:
            if self._chunk_left is None:
                line = self._readline()
                if not line:
                    self.abort()
                sep = line.find(b";")
                if sep >= 0:
                    line = line[:sep]
                try:
                    size = int(line, 16)
                except ValueError:
                    size = -1
                if size < 0:
                    self.abort()
                if size > 0:
                    self._chunk_left = size
                    return size
                while True:
                    line = self._readline()
                    if line == _CRLF or line == _LF:
                        self._chunked = False
                        self._length = self._bytes_read
                        self.close()
                        return 0
                    if not line:
                        self.abort()
            elif self._chunk_left == 0:
                line = self._readline()
                if line != _CRLF and line != _LF:
                    self.abort()
                self._chunk_left = None
            else:
                return self._chunk_left

class HTTPConnection:
    default_port = HTTP_PORT
    response_class = HTTPResponse
    blocksize = 2048
    _merge_buffer_size = 1024

    def __init__(self, host, port=None, timeout=_DEFAULT_TIMEOUT,
                 *, blocksize=None, network=None):
        self._set_host(host, port)
        self.timeout = timeout
        if blocksize is not None:
            self.blocksize = blocksize
        self._network = network
        self._sock = None
        self._resp = None
        self.method = None
        self.url = None
        self._merge_buffer = None
        self._merge_buffmv = None
        self._merged = 0
        self._state = _CS_IDLE

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        return False

    # Clear all per-request state and return the live socket for the caller to close or hand off.
    def _reset(self):
        self._state = _CS_IDLE
        self.method = None
        self.url = None
        self._merged = 0
        self._merge_buffmv = None
        self._merge_buffer = None
        resp, self._resp = self._resp, None
        if resp is not None:
            resp._sock = None
            resp._conn = None
        sock, self._sock = self._sock, None
        return sock

    # Abort the in-flight request. Not a retry: the caller must decide if replaying is safe.
    def _fail_request(self):
        sock = self._reset()
        if sock is not None:
            try: sock.close()
            except OSError: pass

    def close(self):
        sock = self._reset()
        if sock is not None:
            try: sock.close()
            except OSError: pass

    # Hand over the underlying socket (e.g. after a 101 upgrade) without closing it.
    def detach(self):
        if self._state == _CS_HEADERS or self._state == _CS_BODY or self._state == _CS_CHUNKING:
            raise ResponseNotReady()
        return self._reset()

    # Parse host/port. IPv4 and bracketed/IPv6 literals set _hostname=None to skip DNS and TLS SNI.
    def _set_host(self, host, port=None):
        rest = ""
        if host.startswith("["):
            # Bracketed literal: "[addr]" optionally followed by ":port".
            j = host.find("]")
            if j == -1:
                raise InvalidURL()
            self.host, rest = host[:j+1], host[j+1:]
            if rest:
                if not rest.startswith(":"):
                    raise InvalidURL()
                rest = rest[1:]
            self._hostaddr = self.host[1:-1]
            self._hostname = None
        elif host.count(":") > 1:
            # Unbracketed IPv6 literal
            self.host = "[" + host + "]"
            self._hostaddr = host
            self._hostname = None
        else:
            # Hostname or IPv4, optionally with a single ":port".
            i = host.find(":")
            if i >= 0:
                self.host, rest = host[:i], host[i+1:]
            else:
                self.host = host
            len_host = len(self.host)
            if len_host > 0 and _validate(self.host, 0, len_host, 256):
                self._hostaddr = self.host
                self._hostname = None
            else:
                self._hostaddr = self.host
                self._hostname = self.host
        # A port embedded in host wins; otherwise keep the port argument.
        if rest:
            if rest.isdigit():
                port = int(rest, 10)
            else:
                raise InvalidURL()
        if port is None or port == self.default_port:
            self._hostport = self.host.encode()
            self.port = self.default_port
        else:
            self._hostport = b"%s:%d" % (self.host, port)
            self.port = port

    def require_network(self):
        if self._network is not None and not self._network():
            raise NotConnected("network unavailable")

    def connect(self):
        self.close()
        self._open_socket()

    def _open_socket(self):
        self.require_network()
        try:
            self._sock = create_connection((self._hostaddr, self.port), self.timeout)
        except OSError as e:
            if e.errno == errno.ETIMEDOUT:
                raise TimeoutError()
            raise

    def request(self, method, url, body=None, headers=None, *, encode_chunked=None):
        if self._state != _CS_IDLE:
            raise CannotSendRequest()

        skip_host = False
        have_content_length = False
        skip_accept_encoding = False
        have_transfer_encoding = False

        method = _encode_and_validate(method, 3)
        if not method:
            raise ValueError("bad method")
        if not isinstance(method, bytes):
            method = bytes(method)
        if not method.isupper():
            method = method.upper()

        pairs = None
        if headers is not None:
            if isinstance(headers, dict):

                pairs = headers.items()
            elif isinstance(headers, (list, tuple)):
                pairs = headers
            else:
                pairs = list(headers)
            headers = []
            for key, val in pairs:
                key = _normalize_header_name(key, lower=False)
                if key is None:
                    raise ValueError("bad header name")
                if not isinstance(key, bytes):
                    key = bytes(key)
                val = _encode_and_validate(val, 0)
                headers.append((key, val))
                len_key = len(key)
                if len_key == 4:
                    if _containslc(key, 4, b"host", 4):
                        skip_host = True
                elif len_key == 14:
                    if _containslc(key, 14, b"content-length", 14):
                        have_content_length = True
                elif len_key == 15:
                    if _containslc(key, 15, b"accept-encoding", 15):
                        skip_accept_encoding = True
                elif len_key == 17:
                    if _containslc(key, 17, b"transfer-encoding", 17):
                        have_transfer_encoding = True
            del pairs
        else:
            headers = []

        if isinstance(body, str):
            body = body.encode()

        # Framing inference: add Content-Length or Transfer-Encoding only if the caller supplied neither.
        if encode_chunked is None:
            if have_content_length or have_transfer_encoding:
                encode_chunked = False
            elif body is None:
                encode_chunked = False
                if method in _METHODS_EXPECTING_BODY:
                    headers.append((b"Content-Length", b"0"))
                    have_content_length = True
            elif isinstance(body, (bytes, bytearray, memoryview)):
                encode_chunked = False
                headers.append((b"Content-Length", b"%d" % len(body)))
                have_content_length = True
            else:
                encode_chunked = True
                headers.append((b"Transfer-Encoding", b"chunked"))
                have_transfer_encoding = True
        elif encode_chunked and not have_transfer_encoding:
            if have_content_length:
                encode_chunked = False
            else:
                headers.append((b"Transfer-Encoding", b"chunked"))
                have_transfer_encoding = True

        # Request state starts here; the put*/send methods own cleanup if they raise.
        self.putrequest(method, url, skip_host=skip_host, skip_accept_encoding=skip_accept_encoding)

        for key, val in headers:
            self.putheader(key, val)

        self.endheaders(body, encode_chunked=encode_chunked)

    # Read the response. The socket is kept for reuse unless framing forces closing it.
    def getresponse(self, **kwargs):
        if (self._state != _CS_BODY
            or self._resp is not None
            or self._sock is None
            or self._merged):
            raise ResponseNotReady()
        resp = None
        try:
            resp = self.response_class(self._sock, self.method, self.url)
            resp.begin(**kwargs)
            if resp._will_close:
                # The returned response owns the closing socket. The connection
                # has no reusable socket to protect, so it can accept a new
                # request on a fresh socket immediately.
                self._sock = None
                self.method = None
                self.url = None
                self._state = _CS_IDLE
                if resp._length == 0 and resp.status != 101:
                    resp.close()
            else:
                self._state = _CS_RESPONSE
                self._resp = resp
                resp._conn = self
                if resp._length == 0 and not resp._chunked and resp.status != 101:
                    resp.close()
            return resp
        except Exception:
            if resp is not None:
                resp._sock = None
                resp._conn = None
            self._fail_request()
            raise
        finally:

            # Header parsing fragments the heap; collect while the large read buffers are still freeable.
            if _GC_THRESHOLD and gc.mem_free() < _GC_THRESHOLD:
                gc.collect()

    # Auto-opens the socket if needed
    def putrequest(self, method, url, skip_host=False, skip_accept_encoding=False):
        if self._state != _CS_IDLE:
            raise CannotSendRequest()

        method = _encode_and_validate(method, 3)
        if not method:
            raise ValueError("bad method")
        if not isinstance(method, bytes):
            method = bytes(method)
        if not method.isupper():
            method = method.upper()

        url = _encode_and_validate(url, 3)
        if not isinstance(url, bytes):
            url = bytes(url)
        if not url:
            url = b"/"

        if self._sock is None:
            self._open_socket()

        self._merged = 0
        self._resp = None
        self.method = method
        self.url = url
        self._state = _CS_HEADERS

        self._putheaderparts(False, method, b" ", url, b" HTTP/1.1\r\n")

        if not skip_host:
            self._putheaderparts(False, b"Host: ", self._hostport, _CRLF)
        if not skip_accept_encoding:
            self._putheaderparts(False, b"Accept-Encoding: identity\r\n")

    def putheader(self, name, *values, strict=True):
        if self._state != _CS_HEADERS:
            raise CannotSendHeader()
        try:
            name = _encode_and_validate(name, 19)
        except Exception:
            self._fail_request()
            raise

        if not values:
            values = (_BLANK,)
        for v in values:
            try:
                self._putheaderparts(False, name, b": ", _encode_and_validate(v, 0), _CRLF)
            except (ValueError, UnicodeError):
                if strict:
                    self._fail_request()
                    raise


    def putcookie(self, name, value):
        if self._state != _CS_HEADERS:
            raise CannotSendHeader()
        try:
            name = _encode_and_validate(name, 47)
            value = _encode_and_validate(value, 0)
        except Exception:
            self._fail_request()
            raise
        self._putheaderparts(False, b"Cookie: ", name, b"=", value, _CRLF)

    def endheaders(self, message_body=None, *, encode_chunked=False):
        if self._state != _CS_HEADERS:
            raise CannotSendHeader()
        self._putheaderparts(True, _CRLF)
        self._state = _CS_BODY
        if message_body is not None or encode_chunked:
            self.send(message_body, encode_chunked=encode_chunked)

    def send(self, data, *, encode_chunked=False, final_chunk=True):
        if self._state != _CS_BODY and self._state != _CS_CHUNKING:
            raise CannotSendRequest()
        if self._state == _CS_CHUNKING and not encode_chunked:
            raise CannotSendRequest()
        try:
            send = self._send_chunk if encode_chunked else self._send_raw

            if isinstance(data, str):
                data = data.encode()

            if _DEBUG:
                print("send:", type(data).__name__)

            if data is None:
                pass

            elif isinstance(data, (bytes, bytearray, memoryview)):
                send(data)

            elif hasattr(data, "readinto"):
                len_buf = self.blocksize
                buf = bytearray(len_buf)
                bmv = memoryview(buf)
                while True:
                    n = data.readinto(buf)
                    if not n:
                        break
                    if n == len_buf:
                        send(buf)
                    else:
                        send(bmv[:n])

            elif hasattr(data, "read"):
                while True:
                    d = data.read(self.blocksize)
                    if isinstance(d, str):
                        d = d.encode()
                    if not d:
                        break
                    send(d)

            else:
                for d in data:
                    if isinstance(d, str):
                        d = d.encode()
                    if d is not None:
                        send(d)

            if encode_chunked and final_chunk:
                if _DEBUG:
                    print("send: terminator")
                self._send_chunk(None)

            if encode_chunked:
                self._state = _CS_BODY if final_chunk else _CS_CHUNKING

        except Exception:
            self._fail_request()
            raise

    # Coalesce header fragments into one buffer, flushing to the socket as it fills.
    def _putheaderparts(self, flush, *parts):
        try:
            if self._merge_buffer is None and self._merge_buffer_size:
                self._merge_buffer = bytearray(self._merge_buffer_size)
                self._merge_buffmv = memoryview(self._merge_buffer)
            for part in parts:
                if self._merge_buffmv is None:
                    self._send_raw(part)
                    continue
                len_part = len(part)
                if len_part >= self._merge_buffer_size:
                    if self._merged:
                        self._send_raw(self._merge_buffmv[:self._merged])
                        self._merged = 0
                    self._send_raw(part)
                elif self._merged + len_part <= self._merge_buffer_size:
                    self._merge_buffer[self._merged:self._merged+len_part] = part
                    self._merged += len_part
                else:
                    self._send_raw(self._merge_buffmv[:self._merged])
                    self._merge_buffer[:len_part] = part
                    self._merged = len_part
            if flush:
                if self._merged:
                    self._send_raw(self._merge_buffmv[:self._merged])
                    self._merged = 0
                self._merge_buffmv = None
                self._merge_buffer = None
        except Exception:
            self._fail_request()
            raise

    def _send_raw(self, data):
        if not data:
            return
        if _DEBUG:
            print("send:", len(data), "bytes")

        try:
            self.require_network()
        except NotConnected:
            self._fail_request()
            raise

        if self._sock is None:
            self._fail_request()
            raise NotConnected("socket missing")

        try:
            self._sock.sendall(data)
        except OSError as e:
            err = e.errno
            self._fail_request()
            if err == errno.ETIMEDOUT:
                raise TimeoutError()
            if err in _CONNECTION_ERRS:
                raise NotConnected("connection lost")
            raise

    # Send one chunk; None sends the zero-length terminator.
    def _send_chunk(self, data):
        if data is None:
            if _DEBUG:
                print("send: terminating chunk")
            self._send_raw(b"0\r\n\r\n")
            return
        if not data:
            return
        self._send_raw(b"%X\r\n" % len(data))
        self._send_raw(data)
        self._send_raw(_CRLF)

try:
    import ssl
except ImportError:
    pass
else:

    # TLS variant. WARNING: certificate verification is OFF unless you pass an ssl context.
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
            # The TLS handshake needs large contiguous allocations.
            gc.collect()
            raw = self._sock
            try:
                self._sock = self._context.wrap_socket(raw, server_hostname=self._hostname)
            except Exception as e:
                self._sock = None
                if raw is not None:
                    try: raw.close()
                    except OSError: pass
                if isinstance(e, OSError):
                    raise
                elif isinstance(e, MemoryError):
                    raise OSError(errno.ENOMEM)
                else:
                    raise OSError(errno.EIO)
