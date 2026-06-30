# http/client_ish.py
#
# http.client for Micropython, optimised for memory footprint and churn.
# Extensions include chunking, cookies, reconnects, non-blocking I/O and more.

import micropython, socket, errno, gc

HTTP_PORT = const(80)
HTTPS_PORT = const(443)

# Compile-time debug switch: with const(0), the compiler strips every
# "if _DEBUG:" block (and its strings) from the bytecode entirely.
_DEBUG = const(0)

# Methods that get an explicit "Content-Length: 0" when no body is supplied.
_METHODS_EXPECTING_BODY = (b"PATCH", b"POST", b"PUT")

_DEFAULT_TIMEOUT = const(10)

# Run gc.collect() after a response when free memory drops below this (bytes); 0 disables.
_GC_THRESHOLD = const(32768)

_MISSING = object()
_SET_COOKIE = b"set-cookie"
_BLANK = b""
_CRLF = b"\r\n"
_LF = b"\n"

# Exception hierarchy mirroring CPython's http.client.
class HTTPException(Exception): pass
class NotConnected(HTTPException): pass
class TimeoutError(NotConnected): pass
class InvalidURL(HTTPException): pass
class BadStatusLine(HTTPException): pass
class RemoteDisconnected(BadStatusLine): pass
class ImproperConnectionState(HTTPException): pass
class CannotSendRequest(ImproperConnectionState): pass
class CannotSendHeader(ImproperConnectionState): pass
class ResponseNotReady(ImproperConnectionState): pass
class IncompleteRead(HTTPException): pass

# Viper: return 1 if buf[start:end] is free of C0 control chars
@micropython.viper
def _validate(buf:ptr8, start:int, end:int, flags:int) -> int:
    invalid_space = bool(flags & 1)
    invalid_tab   = bool(flags & 2)
    invalid_colon = bool(flags & 4)
    i = start
    while i < end:
        b = buf[i]
        if b == 9:
            if invalid_tab:
                return 0
        elif b < 32:
            return 0
        elif b == 32:
            if invalid_space:
                return 0
        elif b == 58:
            if invalid_colon:
                return 0
        elif b == 127:
            return 0
        i += 1
    return 1

# Coerce a value to bytes and reject control characters in it.
def _encode_and_validate(x, flags):
    if isinstance(x, str):
        x = x.encode()
    elif not isinstance(x, (bytes, bytearray, memoryview)):
        x = str(x).encode()
    if not _validate(x, 0, len(x), flags):
        raise ValueError("not ISO-8859-1")
    return x

# Viper: ASCII-lower-case buf[start:end] into out, or with out==0 just
# report whether it is already lower-case (returns 1 if unchanged).
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

# Return a validated, lower-cased header name, avoiding a copy when possible.
def _normalize_header_name(buf, start=0, end=None, lower=True):
    if isinstance(buf, str):
        buf = buf.encode()
    elif not isinstance(buf, (bytes, bytearray, memoryview)):
        buf = str(buf).encode()
    if end is None:
        end = len(buf)
    if not _validate(buf, start, end, 7):
        return None
    if not lower or _lower_case(buf, start, end, 0):
        if isinstance(buf, memoryview):
            return bytes(buf[start:end])
        if start == 0 and end == len(buf):
            return buf
        return buf[start:end]
    out = bytearray(end - start)
    _lower_case(buf, start, end, out)
    return out

# Viper: transcode Latin-1 to UTF-8. Returns the required output length
# when out==0, or -1 on 0x80-0x9F (C1 controls, invalid in headers).
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

# Decode Latin-1 bytes to str (MicroPython lacks the latin-1 codec).
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

# Response headers kept by default, bucketed by name length for cheap lookup.
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

# Register an extra header to retain when parsing with all_headers=False.
def keep_response_header(name):
    name = _normalize_header_name(name)
    if name is None:
        raise ValueError("invalid header name")
    if not isinstance(name, bytes):
        name = bytes(name)
    len_name = len(name)
    cands = _keep_response_headers.get(len_name)
    if cands is None:
        _keep_response_headers[len_name] = [name]
    elif name not in cands:
        cands.append(name)

# Viper: case-insensitively search for a (lower-case) needle in haystack
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

# Read response headers into a flat [name, value, name, value, ...] list.
# Malformed lines are skipped; unwanted headers are dropped unless all_headers.
def parse_headers(sock, *, all_headers=False, and_cookies=None):
    if and_cookies is None:
        and_cookies = all_headers
    headers = []
    while True:
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

# socket.create_connection() work-alike: try each resolved address in turn.
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

# Streaming response supporting Content-Length, chunked, and read-to-EOF framing.
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

    def __del__(self):
        self.close()

    def close(self):
        sock, self._sock = self._sock, None
        discard = (self._will_close or self._chunked
                or (self._length is not None and self._bytes_read < self._length))
        self._release_conn(discard)
        if sock is not None and discard:
            try: sock.close()
            except OSError: pass

    def abort(self):
        sock, self._sock = self._sock, None
        self._release_conn(True)
        if sock is not None:
            try: sock.close()
            except OSError: pass
        raise IncompleteRead(self._bytes_read, self._length)

    @property
    def closed(self):
        return self._sock is None

    @property
    def chunked(self):
        return self._chunked

    @property
    def length(self):
        return self._length

    @property
    def reason(self):
        if self._reason is None:
            return None
        try:
            return self._reason.strip().decode()
        except UnicodeError:
            return ""

    def fileno(self):
        if self._sock is None:
            return None
        return self._sock.fileno()

    # Read the status line and headers, then work out body framing and keep-alive.
    def begin(self, *, all_headers=False, and_cookies=None):
        if self._headers is not None:
            return
        self._require_blocking()
        self.version, self.status, self._reason = self._read_status()
        if _DEBUG:
            print("status:", repr(self.version), repr(self.status), repr(self.reason))

        self._headers = parse_headers(self._sock, all_headers=all_headers, and_cookies=and_cookies)
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

        # These responses never carry a body.
        if (100 <= self.status < 200
            or self.status == 204 or self.status == 304
            or self.method == b"HEAD"):
            self._chunked = False
            self._length = 0

        # No framing info: body ends only when the server closes the connection.
        if self._length is None and not self._chunked:
            self._will_close = True

    # Decoded (str, str) header pairs; entries that fail Latin-1 decoding are dropped.
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

    # Raw value for name; repeated headers are joined with ", " per RFC 9110.
    def rawheader(self, name, default=None):
        if self._headers is None:
            raise ResponseNotReady()
        name = _normalize_header_name(name)
        if name is None:
            raise ValueError("invalid header name")
        match = None
        for i in range(0, len(self._headers), 2):
            if self._headers[i] == name:
                if match is None:
                    match = self._headers[i+1]
                else:
                    match = match + b", " + self._headers[i+1]
        return default if match is None else match

    def getcookie(self, name, default=None):
        if isinstance(name, str):
            name = name.encode()
        return decode_latin1(self.rawcookie(name, None), default)

    # Extract a cookie's raw value from Set-Cookie headers, stripping quotes.
    # (59/61/34 are ";", "=" and '"'.)
    def rawcookie(self, name, default=None):
        if isinstance(name, str):
            name = name.encode()
        len_name = len(name)
        for key, value in self.rawheaders():
            if key != _SET_COOKIE:
                continue
            if value.startswith(name):
                len_value = len(value)
                if len_value == len_name or value[len_name] == 59:
                    return _BLANK
                if value[len_name] == 61:
                    start = len_name + 1
                    end = value.find(b";", start)
                    if end == -1:
                        end = len_value
                    while start < end and value[start] <= 32: start += 1
                    while end > start and value[end - 1] <= 32: end -= 1
                    if end - start >= 2 and value[start] == 34 and value[end - 1] == 34:
                        start += 1
                        end -= 1
                    return value[start:end]
        return default

    # Read up to amt bytes, or the entire remaining body if amt is None/negative.
    def read(self, amt=None):
        return self._read_impl(None, amt)

    # Single recv-style read: at most one chunk/blocksize of data, possibly short.
    def readshort(self, amt=None):
        return self._read_impl(None, amt, short=True)

    # Fill buf as far as the body allows; returns bytes written (0 = end of body).
    def readinto(self, buf):
        return self._read_impl(buf, None)

    # Yield the body as bytes blocks of up to blocksize.
    def iter_content(self, blocksize=None):
        len_buf = self.blocksize if blocksize is None else blocksize
        buf = bytearray(len_buf)
        bmv = memoryview(buf)
        for n in self.iter_content_into(bmv):
            if n == len_buf:
                yield bytes(buf)
            else:
                yield bytes(bmv[:n])

    # Yield read lengths while repeatedly filling the caller's buffer (zero-copy).
    def iter_content_into(self, bmv):
        if not isinstance(bmv, memoryview):
            bmv = memoryview(bmv)
        while True:
            n = self.readinto(bmv)
            if n == 0:
                return
            yield n

    # Switch to non-blocking reads (recv/recv_into). One-way; disables socket reuse.
    def setblocking(self, flag):
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

    # Non-blocking-friendly read: None while no data is available yet, b"" at end of body.
    def recv(self, amt=None):
        return self._recv_impl(None, amt)

    # Non-blocking-friendly readinto: None while no data is available yet, 0 at end of body.
    def recv_into(self, buf):
        return self._recv_impl(buf, None)

    def _release_conn(self, discard):
        conn, self._conn = self._conn, None
        if conn is not None:
            conn._resp = None
            conn.method = None
            conn.url = None
            if discard:
                conn._sock = None
                conn._can_reconnect = False

    def _require_blocking(self):
        if not self._blocking:
            raise ValueError("operation requires a blocking socket")

    def _require_nonchunked(self):
        if self._chunked:
            raise ValueError("operation requires a non-chunked stream")

    # Parse the status line, transparently skipping 1xx interim responses (except 101).
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

    def _read_impl(self, buf, amt, short=False):
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

        # read-to-EOF: only read() on an unframed body reaches this.
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

        if self._length is not None:
            remaining = self._length - self._bytes_read
            amt = remaining if unbounded else min(amt, remaining)
            unbounded = False
            if amt == 0:
                if remaining == 0:
                    self.close()
                return 0 if into else _BLANK
        elif not unbounded and amt == 0:
            return 0 if into else _BLANK

        # Non-chunked, or a single chunked read (short): one underlying read.
        if short or not self._chunked:
            if short and self._chunked:
                amt = min(amt, self._next_chunk())
                if amt == 0:
                    return 0 if into else _BLANK
            if into:
                n = self._read_wrapper(True, sock.readinto, buf, amt)
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

        # Chunked, accumulate up to amt (read) / fill buf (readinto).
        if into:
            bmv = buf if isinstance(buf, memoryview) else memoryview(buf)
            total = 0
            while total < amt:
                want = min(self._next_chunk(), amt - total)
                if want == 0:
                    break
                n = self._read_wrapper(False, sock.readinto, buf if total == 0 else bmv[total:], want)
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

    def _recv_impl(self, buf, amt):
        self._require_nonchunked()
        into = buf is not None
        if self._sock is None:
            return 0 if into else _BLANK
        if into and not buf:
            return 0
        sock = self._sock

        if into:
            amt = len(buf) if (amt is None or amt < 0) else min(amt, len(buf))
        elif amt is None or amt < 0:
            amt = self.blocksize

        if self._length is not None:
            remaining = self._length - self._bytes_read
            if remaining == 0:
                self.close()
                return 0 if into else _BLANK
            amt = min(amt, remaining)
        if amt == 0:
            return 0 if into else _BLANK

        data = None
        try:
            if not into:
                data = sock.recv(amt)
                n = None if data is None else len(data)
            elif self._have_recv_into:
                n = sock.recv_into(buf, amt)
            elif self._blocking:
                data = sock.recv(min(amt, self.blocksize))
                n = None if data is None else len(data)
            else:
                n = sock.readinto(buf, amt)
        except OSError as e:
            if e.errno == errno.EINTR or e.errno == errno.EAGAIN or e.errno == errno.ETIMEDOUT:
                return None
            sock, self._sock = self._sock, None
            self._release_conn(True)
            if sock is not None:
                try: sock.close()
                except OSError: pass
            raise
        if n is None:
            return None

        # Fallback path produced fresh bytes: copy them into the caller's buffer.
        if into and data is not None:
            buf[:n] = data

        if n == 0:
            if self._length is not None:
                self.abort()
            self.close()
            return 0 if into else _BLANK
        self._bytes_read += n
        if self._length is not None and self._bytes_read >= self._length:
            self.close()
        return n if into else data

    def _read_wrapper(self, resumable, func, *args):
        while True:
            try:
                return func(*args)
            except OSError as e:
                err = e.errno
                if err == errno.EINTR:
                    continue
                if err == errno.EAGAIN and resumable:
                    raise
                if err == errno.ETIMEDOUT and resumable:
                    raise TimeoutError()
                sock, self._sock = self._sock, None
                self._release_conn(True)
                if sock is not None:
                    try: sock.close()
                    except OSError: pass
                raise

    def _readline(self):
        if self._sock is None:
            return None
        return self._read_wrapper(False, self._sock.readline)

    # Advance chunked framing: consume size lines, inter-chunk CRLFs and the
    # trailer as needed; return bytes left in the current chunk (0 = end of body).
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

# http.client.HTTPConnection work-alike with small-write coalescing and
# transparent reconnection of idle keep-alive sockets.
class HTTPConnection:
    default_port = HTTP_PORT
    response_class = HTTPResponse
    auto_open = True
    blocksize = 2048
    _merge_buffer_size = 1024

    def __init__(self, host, port=None, timeout=_DEFAULT_TIMEOUT, network=None):
        self.timeout = timeout
        self._network = network
        self._sock = None
        self._can_reconnect = False
        self._resp = None
        self.method = None
        self.url = None
        self._merge_buffer = None
        self._merge_buffmv = None
        self._merged = 0
        self._set_host(host, port)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        return False

    def __del__(self):
        sock, self._sock = self._sock, None
        if sock is not None:
            try: sock.close()
            except OSError: pass

    # Drop buffers, any pending response, and the socket.
    def close(self):
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
        if sock is not None:
            try: sock.close()
            except OSError: pass
        self._can_reconnect = False

    # Hand over the underlying socket (e.g. after a 101 upgrade) and reset.
    def detach(self):
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
        self._can_reconnect = False
        return sock

    # Record host/port; IPv6 ([...]) and IPv4 literals skip DNS and TLS SNI.
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
            if len(self.host) > 0 and all(c in "0123456789." for c in self.host):
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
        self.require_network()
        try:
            self._sock = create_connection((self._hostaddr, self.port), self.timeout)
        except OSError as e:
            if e.errno == errno.ETIMEDOUT:
                raise TimeoutError()
            raise

    # Convenience wrapper: send request line, headers and body in one call.
    def request(self, method, url, body=None, headers=None, *, encode_chunked=None):
        skip_host = False
        have_content_length = False
        skip_accept_encoding = False
        have_transfer_encoding = False

        pairs = None
        if headers is not None:
            if isinstance(headers, dict):
                # items() view is re-iterable, so no list copy is needed
                # for the two passes below.
                pairs = headers.items()
            elif isinstance(headers, (list, tuple)):
                pairs = headers
            else:
                pairs = list(headers)
            headers = []
            for name, value in pairs:
                name = _normalize_header_name(name, lower=False)
                if name is None:
                    raise ValueError("invalid header name")
                value = _encode_and_validate(value, 0)
                headers.append((name, value))
                len_name = len(name)
                if len_name == 4:
                    if _containslc(name, 4, b"host", 4):
                        skip_host = True
                elif len_name == 14:
                    if _containslc(name, 14, b"content-length", 14):
                        have_content_length = True
                elif len_name == 15:
                    if _containslc(name, 15, b"accept-encoding", 15):
                        skip_accept_encoding = True
                elif len_name == 17:
                    if _containslc(name, 17, b"transfer-encoding", 17):
                        have_transfer_encoding = True
            del pairs
        else:
            headers = []

        self.putrequest(method, url, skip_host=skip_host, skip_accept_encoding=skip_accept_encoding)

        if isinstance(body, str):
            body = body.encode()

        # Infer framing: known-length bodies get Content-Length, streams get chunked.
        if encode_chunked is None:
            if body is None:
                encode_chunked = False
                if not have_content_length and self.method in _METHODS_EXPECTING_BODY:
                    headers.append((b"Content-Length", b"0"))
            elif isinstance(body, (bytes, bytearray, memoryview)):
                encode_chunked = False
                if not have_content_length:
                    headers.append((b"Content-Length", b"%d" % len(body)))
            else:
                encode_chunked = not have_content_length
        if encode_chunked and not have_transfer_encoding:
            headers.append((b"Transfer-Encoding", b"chunked"))

        for name, value in headers:
            self.putheader(name, value)

        self.endheaders(body, encode_chunked=encode_chunked)

    # Read the response to the last request. The socket is kept for reuse
    # unless the response framing requires closing it.
    def getresponse(self, **kwargs):
        if (self._resp is not None
            or self.method is None
            or self._sock is None
            or self._can_reconnect
            or self._merged):
            raise ResponseNotReady()
        resp = None
        try:
            resp = self.response_class(self._sock, self.method, self.url)
            resp.begin(**kwargs)
            if resp._will_close:
                self._sock = None
            else:
                self._resp = resp
                resp._conn = self
                if resp._length == 0 and not resp._chunked:
                    resp.close()
            return resp
        except Exception:
            if resp is not None:
                resp._sock = None
            sock, self._sock = self._sock, None
            if sock is not None:
                try: sock.close()
                except OSError: pass
            raise
        finally:
            # Help small heaps: header parsing fragments memory.
            if _GC_THRESHOLD and gc.mem_free() < _GC_THRESHOLD:
                gc.collect()

    # Start a request: send the request line plus default Host and
    # Accept-Encoding headers (suppressed if the caller provides their own).
    def putrequest(self, method, url, skip_host=False, skip_accept_encoding=False):
        if (self.method is not None and self._sock is not None
                and (self._resp is None or not self._resp.closed)):
            raise CannotSendRequest()
        self._merged = 0
        self._resp = None
        self._can_reconnect = self.auto_open

        method = _encode_and_validate(method, 3)
        if not isinstance(method, bytes):
            method = bytes(method)

        url = _encode_and_validate(url, 3)
        if not isinstance(url, bytes):
            url = bytes(url)
        if not url:
            url = b"/"

        self.method = method
        self.url = url
        self._putheaderparts(False, method, b" ", url, b" HTTP/1.1\r\n")

        if not skip_host:
            self._putheaderparts(False, b"Host: ", self._hostport, _CRLF)
        if not skip_accept_encoding:
            self._putheaderparts(False, b"Accept-Encoding: identity\r\n")

    def putheader(self, name, *values):
        if self._resp is not None or self.method is None:
            raise CannotSendHeader()
        name = _encode_and_validate(name, 7)
        if not values:
            self._putheaderparts(False, name, b":\r\n")
            return
        if len(values) == 1:
            values = _encode_and_validate(values[0], 0)
        else:
            values = b"\r\n\t".join(_encode_and_validate(v, 0) for v in values)
        self._putheaderparts(False, name, b": ", values, _CRLF)

    # Send a Cookie header; the value is quoted unless it already contains quotes.
    def putcookie(self, name, value):
        if self._resp is not None or self.method is None:
            raise CannotSendHeader()
        name = _encode_and_validate(name, 3)
        value = _encode_and_validate(value, 0)
        if not value or value.find(b'"') >= 0:
            self._putheaderparts(False, b"Cookie: ", name, b"=", value, _CRLF)
        else:
            self._putheaderparts(False, b"Cookie: ", name, b'="', value, b'"', _CRLF)

    # Terminate the header block with a blank line and optionally send the body.
    def endheaders(self, message_body=None, *, encode_chunked=False):
        if self._resp is not None or self.method is None:
            raise CannotSendHeader()
        self._putheaderparts(True, _CRLF)
        if message_body is not None or encode_chunked:
            self.send(message_body, encode_chunked=encode_chunked)

    # Send a body: bytes-like, str, a stream with readinto(), or an iterable of chunks.
    def send(self, data, *, encode_chunked=False, final_chunk=True):
        if self._resp is not None:
            raise CannotSendRequest()
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

    # Append parts to the merge buffer, flushing to the socket as it fills
    # (or unconditionally when flush=True).
    def _putheaderparts(self, flush, *parts):
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
        if flush and self._merged:
            merged, self._merged = self._merged, 0
            self._send_raw(self._merge_buffmv[:merged])

    # Write to the socket, reconnecting once if an idle keep-alive
    # connection turns out to have been dropped by the server.
    def _send_raw(self, data):
        if not data:
            return
        if _DEBUG:
            print("send:", len(data), "bytes")

        try:
            self.require_network()
        except NotConnected:
            if self._can_reconnect:
                self.method = None
                self.url = None
                resp, self._resp = self._resp, None
                if resp is not None:
                    resp._sock = None
                    resp._conn = None
                sock, self._sock = self._sock, None
                if sock is not None:
                    try: sock.close()
                    except OSError: pass
                self._can_reconnect = False
            raise

        if self._can_reconnect:
            if self._sock is not None:
                try:
                    self._sock.sendall(data)
                    self._can_reconnect = False
                    return
                except OSError:
                    sock, self._sock = self._sock, None
                    if sock is not None:
                        try: sock.close()
                        except OSError: pass

            try:
                self.connect()
            except TimeoutError:
                self._sock = None
                self._can_reconnect = False
                raise
            except OSError as e:
                sock, self._sock = self._sock, None
                if sock is not None:
                    try: sock.close()
                    except OSError: pass
                self._can_reconnect = False
                raise NotConnected(str(e))

        if self._sock is None:
            raise NotConnected("socket missing")

        try:
            self._sock.sendall(data)
        except OSError as e:
            sock, self._sock = self._sock, None
            if sock is not None:
                try: sock.close()
                except OSError: pass
            self._can_reconnect = False
            if e.errno == errno.ETIMEDOUT:
                raise TimeoutError()
            raise NotConnected(str(e))

        self._can_reconnect = False

    # Send one chunked-encoding chunk; None sends the zero-length terminator.
    def _send_chunk(self, data):
        if data is None:
            if _DEBUG:
                print("send: terminating chunk")
            self._send_raw(b"0\r\n\r\n")
            return
        if not data:
            return
        len_data = len(data)
        header = b"%X\r\n" % len_data
        if self._merge_buffer is not None and self._merged == 0:
            len_header = len(header)
            total = len_header + len_data + 2
            if total <= self._merge_buffer_size:
                self._merge_buffer[:len_header] = header
                self._merge_buffer[len_header:len_header+len_data] = data
                self._merge_buffer[len_header+len_data:total] = _CRLF
                self._send_raw(self._merge_buffmv[:total])
                return
        self._send_raw(header)
        self._send_raw(data)
        self._send_raw(_CRLF)

try:
    import ssl
except ImportError:
    pass
else:
    # TLS variant. NOTE: certificate verification is OFF by default;
    # pass an ssl context to enable it.
    class HTTPSConnection(HTTPConnection):
        default_port = HTTPS_PORT

        def __init__(self, *args, context=None, **kwargs):
            super().__init__(*args, **kwargs)
            if context is None:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.verify_mode = ssl.CERT_NONE
            self._context = context

        def connect(self):
            super().connect()
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
