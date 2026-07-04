# http/client_ish.py
#
# http.client for Micropython, optimised for memory footprint and churn.
# Extensions include chunking, cookies, non-blocking I/O and more.

import micropython, socket, errno, gc

# Default TCP ports used by the connection classes.
HTTP_PORT = const(80)
HTTPS_PORT = const(443)

# Tunables kept as consts so MicroPython can optimise them.
_DEBUG = const(0)
_DEFAULT_TIMEOUT = const(10)
_METHODS_EXPECTING_BODY = (b"PATCH", b"POST", b"PUT")
_GC_THRESHOLD = const(32768)

# HTTPConnection state machine values.
_CS_IDLE     = const(0)
_CS_HEADERS  = const(1)
_CS_BODY     = const(2)
_CS_CHUNKING = const(3)
_CS_RESPONSE = const(4)

# Small shared sentinels/constants to avoid repeated allocations.
_MISSING = object()
_SET_COOKIE = b"set-cookie"
_CR = b"\r"
_LF = b"\n"
_CRLF = b"\r\n"
_BLANK = b""

# Errnos that mean a non-blocking operation should be retried later.
_WOULDBLOCK_ERRS = (
    errno.EAGAIN,
    errno.EALREADY,
    errno.EINPROGRESS,
    getattr(errno, "EWOULDBLOCK", None),
)

# Errnos that indicate the peer or network dropped the connection.
_CONNECTION_ERRS = (
    errno.ECONNABORTED,
    errno.ECONNREFUSED,
    errno.ECONNRESET,
    errno.EHOSTUNREACH,
    errno.ENOTCONN,
    getattr(errno, "EHOSTDOWN", None),
    getattr(errno, "ENETDOWN", None),
    getattr(errno, "ENETRESET", None),
    getattr(errno, "ENETUNREACH", None),
    getattr(errno, "EPIPE", None),
    getattr(errno, "ESHUTDOWN", None),
    getattr(errno, "ECANCELED", None),
    getattr(errno, "EIO", None),
)

# Resource shortages that can succeed on a later retry.
_TRANSIENT_ERRNOS = (
    getattr(errno, "ENOBUFS", None),
    getattr(errno, "EADDRNOTAVAIL", None),
)

# Exception hierarchy mirrors common HTTP client errors while marking retryable cases.
class Transient(Exception): pass

class HTTPException(Exception): pass
class NotConnected(Transient, HTTPException):
    def __init__(self, reason="lost"):
        super().__init__(reason)
        self.reason = reason
class InvalidURL(HTTPException): pass
class IncompleteRead(HTTPException):
    def __init__(self, bytes_read=None, length=None):
        super().__init__(bytes_read, length)
        if bytes_read is not None and length is not None:
            self.expected = length - bytes_read
        else:
            self.expected = None
class ImproperConnectionState(HTTPException): pass
class CannotSendRequest(ImproperConnectionState): pass
class CannotSendHeader(ImproperConnectionState): pass
class ResponseNotReady(ImproperConnectionState): pass
class BadStatusLine(HTTPException): pass
class RemoteDisconnected(BadStatusLine, Transient): pass
class TimeoutError(NotConnected, OSError):
    def __init__(self, reason="timeout"):
        OSError.__init__(self, errno.ETIMEDOUT)
        self.errno = errno.ETIMEDOUT
        self.reason = reason

RETRYABLE = (Transient, IncompleteRead)

# Retry only when the request can be safely replayed.
def safe_to_retry(exc, *, sent=True, idempotent=False, replayable=True):
    if isinstance(exc, Transient):
        if not sent:
            return True
        return idempotent and replayable
    if isinstance(exc, IncompleteRead):
        return idempotent and replayable
    if isinstance(exc, MemoryError):
        gc.collect()
        return idempotent and replayable
    return False

# Viper keeps hot-path byte validation fast and allocation-free.
@micropython.viper
def _validate(buf:ptr8, start:int, end:int, flags:int) -> int:
    invalid_space     = bool(flags & 1)
    invalid_tab       = bool(flags & 2)
    invalid_dquote    = bool(flags & 4)
    invalid_comma     = bool(flags & 8)
    invalid_colon     = bool(flags & 16)
    invalid_semicolon = bool(flags & 32)
    invalid_equals    = bool(flags & 64)
    invalid_backslash = bool(flags & 128)
    check_ip4addr     = bool(flags & 256)
    # Flags describe which ASCII punctuation is disallowed for the current field.
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
        elif b == 34:
            if invalid_dquote:
                return 0
        elif b == 44:
            if invalid_comma:
                return 0
        elif b == 58:
            if invalid_colon:
                return 0
        elif b == 59:
            if invalid_semicolon:
                return 0
        elif b == 61:
            if invalid_equals:
                return 0
        elif b == 92:
            if invalid_backslash:
                return 0
        elif b == 127:
            return 0
        i += 1
    return 1

# Convert user input to bytes, then reject unsafe control/separator chars.
def _encode_and_validate(x, flags):
    if isinstance(x, str):
        x = x.encode()
    elif not isinstance(x, (bytes, bytearray, memoryview)):
        x = str(x).encode()
    if not _validate(x, 0, len(x), flags):
        raise ValueError("invalid character")
    return x

# Return whether the slice is already lower-case, or write a lower-case copy.
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

# Normalise header names while preserving the original object when possible.
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

# HTTP header text is latin-1; this converts it to UTF-8 for MicroPython strings.
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

# Decode a header value, returning default instead of raising when requested.
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

# Headers retained by default; grouped by length for cheap matching.
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

# Allow callers to preserve additional response headers without parsing all of them.
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

# Case-insensitive contains check where the needle is already lower-case.
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

# Parse response headers into alternating name/value byte entries.
def parse_headers(sock, *, all_headers=False, and_cookies=None):
    if and_cookies is None:
        and_cookies = all_headers
    headers = []
    while True:
        if callable(sock):
            line = sock()
        else:
            line = sock.readline()

        if line == _CRLF or line == _LF:
            return headers

        if not line or not line.endswith(_LF):
            raise RemoteDisconnected()

        # Skip obsolete folded/continuation lines instead of buffering them.
        if line[0] <= 32:
            continue

        sep = line.find(b":")
        if sep == -1:
            continue

        end = sep
        while end > 0 and line[end - 1] <= 32: end -= 1

        name = None
        # Fast path: only keep known headers unless all_headers=True.
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

# Resolve all addresses and connect to the first reachable endpoint.
def create_connection(address, timeout=None):
    host, port = address
    try:
        infos = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)
    except OSError:
        raise NotConnected("dns")
    err = None
    for f, t, p, _, a in infos:
        sock = None
        try:
            sock = socket.socket(f, t, p)
            if timeout != 0:
                sock.settimeout(timeout)
            # Low-latency writes are preferred for small HTTP header/body chunks.
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

# Lightweight HTTP response reader with fixed-length, close-delimited, and chunked support.
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

        # Body framing discovered from response headers.
        self._chunked = False
        self._chunk_left = None
        self._length = None
        self._will_close = True
        self._bytes_read = 0

        # Non-blocking mode is only allowed after headers and only for non-chunked bodies.
        self._blocking = True
        self._severed = False
        self._have_recv = hasattr(sock, "recv")
        self._have_recv_into = hasattr(sock, "recv_into")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        return False

    # Return a reusable socket to HTTPConnection, or mark it unusable.
    def _release_conn(self, discard):
        conn, self._conn = self._conn, None
        if conn is not None:
            conn._resp = None
            conn.method = None
            conn.url = None
            conn._state = _CS_IDLE
            if discard:
                conn._sock = None

    def detach(self):
        sock, self._sock = self._sock, None
        self._release_conn(True)
        return sock

    def _teardown(self, discard):
        sock, self._sock = self._sock, None
        self._release_conn(discard)
        if sock is not None and discard:
            try: sock.close()
            except OSError: pass

    def close(self):
        # Keep the connection only when the full, non-upgrade body was consumed.
        discard = (self._will_close or self._chunked or self.status == 101
                or (self._length is not None and self._bytes_read < self._length))
        self._teardown(discard)

    def abort(self):
        self._severed = True
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

    # Read the status line and headers, then decide how the body is framed.
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

        # Scan only the retained headers needed for body and connection handling.
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

        # These responses never carry a message body.
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

    def getheader(self, name, default=None):
        return decode_latin1(self.rawheader(name, None), default)

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

    def getcookie(self, name, default=None):
        rawvalue = self.getrawcookie(name, None)
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

    def getrawcookie(self, name, default=None):
        if isinstance(name, str):
            name = name.encode()
        len_name = len(name)
        for key, val in self.rawheaders():
            if key != _SET_COOKIE:
                continue
            if val.startswith(name):
                len_val = len(val)
                if len_val == len_name or val[len_name] == 59:
                    return _BLANK
                if val[len_name] == 61:
                    return val[len_name+1:]
        return default

    # Convert socket errors into HTTP-specific exceptions and close bad sockets.
    def _read_wrapper(self, resumable, func, *args):
        while True:
            try:
                return func(*args)
            except OSError as e:
                err = e.errno
                if err == errno.EINTR:
                    continue
                if resumable and err in _WOULDBLOCK_ERRS:
                    raise
                self._severed = True
                self._teardown(True)
                if err == errno.ETIMEDOUT:
                    raise TimeoutError()
                if err in _CONNECTION_ERRS or err in _TRANSIENT_ERRNOS:
                    raise NotConnected("lost")
                raise
            except BaseException:
                self._severed = True
                self._teardown(True)
                raise

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

    def _append_read_data(self, out, data):
        if out is _BLANK:
            return data
        if type(out) is bytes:
            out = bytearray(out)
        out.extend(data)
        return out

    # Shared implementation for read/readshort/readinto/recv variants.
    def _read_impl(self, buf, amt, short=False, non_blocking=False):
        if self._headers is None:
            raise ResponseNotReady()
        if non_blocking:
            # Non-blocking reads return None when no data is ready yet.
            self._require_nonchunked()
        else:
            self._require_blocking()

        into = buf is not None
        if self._severed:
            raise NotConnected("severed")
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
            if unbounded and (short or non_blocking):
                amt = self.blocksize
                unbounded = False

        if not unbounded and amt == 0:
            return 0 if into else _BLANK

        if self._length is not None:
            # Never read past Content-Length.
            remaining = self._length - self._bytes_read
            if remaining == 0:
                self.close()
                return 0 if into else _BLANK
            if unbounded:
                amt = remaining
                unbounded = False
            else:
                amt = min(amt, remaining)

        if non_blocking:
            try:
                if into:
                    if self._have_recv_into:
                        n = sock.recv_into(buf, amt)
                    else:
                        n = sock.readinto(buf, amt)
                    data = None
                else:
                    if self._have_recv:
                        data = sock.recv(amt)
                    else:
                        data = sock.read(amt)
                    n = None if data is None else len(data)
            except OSError as e:
                err = e.errno
                if err in _WOULDBLOCK_ERRS or err == errno.EINTR:
                    return None
                self._severed = True
                self._teardown(True)
                if err == errno.ETIMEDOUT:
                    raise TimeoutError()
                if err in _CONNECTION_ERRS or err in _TRANSIENT_ERRNOS:
                    raise NotConnected("lost")
                raise
            except BaseException:
                self._severed = True
                self._teardown(True)
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

        if short or into:
            if short and self._chunked:
                amt = min(amt, self._next_chunk())
                if amt == 0:
                    return 0 if into else _BLANK

            if self._chunked and into and not short:
                # Chunked readinto may span several chunks.
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

        # From here on, read() is a fill API: it keeps reading until amt bytes
        # have been decoded, the logical body ends, or a protocol/transport
        # error occurs.
        if self._chunked:
            out = _BLANK
            len_out = 0
            while unbounded or len_out < amt:
                avail = self._next_chunk()
                if unbounded:
                    want = min(avail, self.blocksize)
                else:
                    want = min(amt - len_out, avail, self.blocksize)
                if want == 0:
                    break
                chunk = self._read_wrapper(False, sock.read, want)
                if not chunk:
                    self.abort()
                len_chunk = len(chunk)
                self._bytes_read += len_chunk
                self._chunk_left -= len_chunk
                len_out += len_chunk
                out = self._append_read_data(out, chunk)
            return out

        # Fixed-length and close-delimited bodies.  For fixed-length bodies, amt
        # has already been clamped to the remaining Content-Length.  For
        # close-delimited bodies, EOF is the normal body terminator.
        out = _BLANK
        len_out = 0
        while unbounded or len_out < amt:
            if unbounded:
                want = self.blocksize
            else:
                want = min(amt - len_out, self.blocksize)
            if want == 0:
                break
            data = self._read_wrapper(False, sock.read, want)
            if not data:
                if self._length is not None:
                    self.abort()
                self.close()
                break
            len_data = len(data)
            self._bytes_read += len_data
            len_out += len_data
            out = self._append_read_data(out, data)
            if self._length is not None and self._bytes_read >= self._length:
                self.close()
                break
        return out

    # Stream the body without holding the full response in memory.
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

    # After switching to non-blocking mode, the connection cannot be reused.
    def setblocking(self, flag):
        if self._headers is None:
            raise ResponseNotReady()
        if self._sock is None:
            raise NotConnected("socket")
        if flag:
            raise ValueError("can only transition to non-blocking")
        self._require_nonchunked()
        sock = self._sock
        if sock is not None:
            sock.setblocking(False)
        self._release_conn(True)
        self._blocking = False
        self._will_close = True

    # Hand the socket to asyncio after detaching it from this response.
    def as_async_stream(self):
        if self._sock is None:
            return None
        import asyncio
        self.setblocking(False)
        sock, self._sock = self._sock, None
        return asyncio.StreamReader(sock)

    def _require_blocking(self):
        if not self._blocking:
            raise ValueError("operation requires a blocking socket")

    def _require_nonchunked(self):
        if self._chunked:
            raise ValueError("operation requires a non-chunked stream")

    def _readline(self):
        if self._sock is None:
            return None
        return self._read_wrapper(False, self._sock.readline)

    def _read_status_line(self):
        while True:
            if self._sock is None:
                raise RemoteDisconnected()
            first = self._read_wrapper(False, self._sock.read, 1)
            if not first:
                raise RemoteDisconnected()
            if self._conn is not None:
                self._conn.response_started = True
            if first == _CR or first == _LF:
                continue
            if first != b"H":
                raise BadStatusLine()
            rest = self._readline()
            if not rest or not rest.endswith(_LF):
                raise RemoteDisconnected()
            return rest

    # Consume informational 1xx responses before returning the final status.
    def _read_status(self):
        while True:
            line = self._read_status_line()
            if _DEBUG:
                print("status-H: ", repr(line))
            if not line.startswith(b"TTP/"):
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

        if version == b"TTP/1.0":
            version = 10
        elif version.startswith(b"TTP/1."):
            version = 11
        else:
            raise BadStatusLine()

        return version, status, reason

    # Return bytes left in the current chunk, parsing new chunk headers as needed.
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
                    self._severed = True
                    self._teardown(True)
                    raise IncompleteRead(self._bytes_read, self._length)
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
                if not line:
                    self.abort()
                if line != _CRLF and line != _LF:
                    self._severed = True
                    self._teardown(True)
                    raise IncompleteRead(self._bytes_read, self._length)
                self._chunk_left = None
            else:
                return self._chunk_left

# Minimal HTTP/1.1 client connection with optional keep-alive reuse.
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
        self.request_sent = False
        self.response_started = False
        self._merge_buffer = None
        self._merged = 0
        self._state = _CS_IDLE

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        return False

    # Drop all request/response state and detach any active response.
    def _reset(self):
        self._state = _CS_IDLE
        self.method = None
        self.url = None
        self._merged = 0
        self._merge_buffer = None
        resp, self._resp = self._resp, None
        if resp is not None:
            resp._sock = None
            resp._conn = None
            resp._severed = True
        sock, self._sock = self._sock, None
        return sock

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

    def detach(self):
        if self._state == _CS_RESPONSE:
            raise ImproperConnectionState("response active; use response.detach()")
        if self._state != _CS_IDLE:
            raise ResponseNotReady()
        return self._reset()

    # Parse host[:port], including bracketed and raw IPv6 literals.
    def _set_host(self, host, port=None):
        rest = ""
        if host.startswith("["):
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
            self.host = "[" + host + "]"
            self._hostaddr = host
            self._hostname = None
        else:
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

    # Optional hook lets callers fail fast when the network is known down.
    def require_network(self):
        if self._network is not None and not self._network():
            raise NotConnected("network")

    def connect(self):
        self.close()
        self.request_sent = False
        self.response_started = False
        self._open_socket()

    # Open a TCP socket and normalise common connection failures.
    def _open_socket(self):
        try:
            self._sock = create_connection((self._hostaddr, self.port), self.timeout)
        except OSError as e:
            err = e.errno
            if err == errno.ETIMEDOUT:
                raise TimeoutError("connect")
            if err is not None and (err < 0 or err in _CONNECTION_ERRS
                                    or err in _TRANSIENT_ERRNOS):
                raise NotConnected("connect")
            raise

    # Convenience wrapper that builds headers, sends the request, and writes the body.
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

        # Choose Content-Length when possible; otherwise fall back to chunked upload.
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

        self.putrequest(method, url, skip_host=skip_host, skip_accept_encoding=skip_accept_encoding)

        for key, val in headers:
            self.putheader(key, val)

        self.endheaders(body, encode_chunked=encode_chunked)

    # Finalise the request by parsing the response and tracking socket reusability.
    def getresponse(self, **kwargs):
        if (self._state != _CS_BODY
            or self._resp is not None
            or self._sock is None
            or self._merged):
            raise ResponseNotReady()
        resp = None
        try:
            resp = self.response_class(self._sock, self.method, self.url)
            resp._conn = self
            resp.begin(**kwargs)
            if resp._will_close:
                self._sock = None
                self.method = None
                self.url = None
                self._state = _CS_IDLE
                resp._conn = None
                if resp._length == 0 and resp.status != 101:
                    resp.close()
            else:
                self._state = _CS_RESPONSE
                self._resp = resp
                if resp._length == 0 and resp.status != 101 and not resp._chunked:
                    resp.close()
            return resp
        except BaseException:
            if resp is not None:
                if resp._sock is None:
                    self._sock = None
                resp._sock = None
                resp._conn = None
            self._fail_request()
            raise
        finally:
            if _GC_THRESHOLD and gc.mem_free() < _GC_THRESHOLD:
                gc.collect()

    # Start the request line and mandatory default headers.
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

        self.request_sent = False
        self.response_started = False
        self.require_network()
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

    # Add one header line per supplied value.
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
            name = _encode_and_validate(name, 239)
            value = _encode_and_validate(value, 32)
        except Exception:
            self._fail_request()
            raise
        self._putheaderparts(False, b"Cookie: ", name, b"=", value, _CRLF)

    def putrawcookie(self, value):
        if self._state != _CS_HEADERS:
            raise CannotSendHeader()
        try:
            value = _encode_and_validate(value, 0)
        except Exception:
            self._fail_request()
            raise
        self._putheaderparts(False, b"Cookie: ", value, _CRLF)

    # Finish the header section and optionally send the body immediately.
    def endheaders(self, message_body=None, *, encode_chunked=False):
        if self._state != _CS_HEADERS:
            raise CannotSendHeader()
        try:
            # Flush request line and header fields before the commit point.
            # If this fails, the terminating blank line was not written by us.
            self._putheaderparts(True)

            # Commit point: once this write is attempted, the server may have
            # seen the blank line that makes the request application-visible.
            self.request_sent = True
            self._send_raw(_CRLF)

            self._state = _CS_BODY
            if message_body is not None or encode_chunked:
                self.send(message_body, encode_chunked=encode_chunked)
        except Exception:
            self._fail_request()
            raise

    # Send bytes, strings, file-like objects, or iterables as the request body.
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

    # Merge tiny header fragments into one buffer before writing to the socket.
    def _putheaderparts(self, flush, *parts):
        try:
            buf = self._merge_buffer
            if buf is None:
                if not self._merge_buffer_size:
                    for part in parts:
                        self._send_raw(part)
                    return
                buf = self._merge_buffer = bytearray(self._merge_buffer_size)
            size = len(buf)
            for part in parts:
                len_part = len(part)
                if len_part >= size:
                    if self._merged:
                        self._send_raw(memoryview(buf)[:self._merged])
                        self._merged = 0
                    self._send_raw(part)
                elif self._merged + len_part <= size:
                    buf[self._merged:self._merged+len_part] = part
                    self._merged += len_part
                else:
                    self._send_raw(memoryview(buf)[:self._merged])
                    buf[:len_part] = part
                    self._merged = len_part
            if flush:
                if self._merged:
                    self._send_raw(memoryview(buf)[:self._merged])
                    self._merged = 0
                self._merge_buffer = None
        except Exception:
            self._fail_request()
            raise

    # Send all bytes or convert socket failure into a connection-level error.
    def _send_raw(self, data):
        if not data:
            return
        if _DEBUG:
            print("send:", len(data), "bytes")

        if self._sock is None:
            self._fail_request()
            raise NotConnected("socket")

        try:
            self._sock.sendall(data)
        except OSError as e:
            err = e.errno
            self._fail_request()
            if err == errno.ETIMEDOUT:
                raise TimeoutError()
            if err in _CONNECTION_ERRS or err in _TRANSIENT_ERRNOS:
                raise NotConnected("lost")
            raise

    # Write one HTTP chunk, or the terminating zero-length chunk.
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

    # HTTPS variant wraps the TCP socket with MicroPython SSL support.
    class HTTPSConnection(HTTPConnection):
        default_port = HTTPS_PORT

        def __init__(self, *args, context=None, **kwargs):
            super().__init__(*args, **kwargs)
            if context is None:
                # Default context favours compatibility on devices without CA stores.
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.verify_mode = ssl.CERT_NONE
            self._context = context

        # Replace the raw socket with a TLS-wrapped socket.
        def _open_socket(self):
            super()._open_socket()
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
                    err = e.errno
                    if err == errno.ETIMEDOUT:
                        raise TimeoutError("tls")
                    if err in _CONNECTION_ERRS or err in _TRANSIENT_ERRNOS:
                        raise NotConnected("tls")
                    raise
                if isinstance(e, MemoryError):
                    raise OSError(errno.ENOMEM)
                raise OSError(errno.EIO, str(e))
