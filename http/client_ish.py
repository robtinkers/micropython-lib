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
class InvalidURL(HTTPException): pass
class BadStatusLine(HTTPException): pass
class RemoteDisconnected(BadStatusLine): pass
class ImproperConnectionState(HTTPException): pass
class CannotSendRequest(ImproperConnectionState): pass
class CannotSendHeader(ImproperConnectionState): pass
class ResponseNotReady(ImproperConnectionState): pass
class IncompleteRead(HTTPException): pass

#
import network, time

class WifiManager:
    def __init__(self, *args, reset=False, timeout=10):
        self._nic = network.WLAN(network.WLAN.IF_STA)
        self._args = args
        self._reset = reset
        self._timeout = timeout

    def connect(self):
        was_active = self._nic.active()
        if was_active:
            if self._nic.isconnected():
                return True
            if self._reset:
                self._disconnect()
                was_active = False
        if not was_active:
            self._nic.active(True)
            time.sleep(1)
        self._nic.connect(*self._args)
        t0, timeout_ms = time.ticks_ms(), self._timeout * 1000
        while True:
            if self._nic.isconnected():
                return True
            if time.ticks_diff(time.ticks_ms(), t0) > timeout_ms:
                self._disconnect()
                return False
            time.sleep_ms(100)

    def _disconnect(self):
        try: self._nic.disconnect()
        except Exception: pass
        time.sleep(1)
        if self._nic.active():
            self._nic.active(False)
            time.sleep(1)

# Viper: return 1 if buf[start:end] is free of C0 control chars
# (invalid_flags bit 0 also forbids space and tab).
@micropython.viper
def _validate_not_c0(buf:ptr8, start:int, end:int, invalid_flags:int) -> int:
    invalid_space = invalid_flags & 1
    i = start
    while i < end:
        b = buf[i]
        if b < 33:
            if invalid_space or (b != 9 and b != 32):
                return 0
        i += 1
    return 1

# Coerce a value to bytes and reject control characters in it.
def _encode_and_validate(val, invalid_flags):
    if isinstance(val, str):
        val = val.encode()
    elif not isinstance(val, (bytes, bytearray, memoryview)):
        val = str(val).encode()
    if not _validate_not_c0(val, 0, len(val), invalid_flags):
        raise ValueError("not ISO-8859-1")
    return val

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

# Return a validated, lower-cased header key, avoiding a copy when possible.
def _normalize_key(buf, start=0, end=None, lower=True):
    if isinstance(buf, str):
        buf = buf.encode()
    elif not isinstance(buf, (bytes, bytearray, memoryview)):
        buf = str(buf).encode()
    if end is None:
        end = len(buf)
    if not _validate_not_c0(buf, start, end, 1):
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
            raise UnicodeError
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
            raise UnicodeError
        return default
    utf8out = bytearray(utf8len)
    _latin1_to_utf8(buf, len_buf, utf8out)
    return utf8out.decode()

# Response headers kept by default, bucketed by key length for cheap lookup.
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
def keep_response_header(key):
    key = _normalize_key(key)
    if key is None:
        raise ValueError("invalid key")
    if not isinstance(key, bytes):
        key = bytes(key)
    len_key = len(key)
    cands = _keep_response_headers.get(len_key)
    if cands is None:
        _keep_response_headers[len_key] = [key]
    elif key not in cands:
        cands.append(key)

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

# Read response headers into a flat [key, value, key, value, ...] list.
# Malformed lines are skipped; unwanted headers are dropped unless all_headers.
def parse_headers(sock, *, all_headers=False, and_cookies=None):
    if and_cookies is None:
        and_cookies = all_headers
    headers = []
    _append = headers.append
    _readline = sock.readline
    _get = _keep_response_headers.get
    while True:
        line = _readline()

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

        key = None
        cands = _get(end)
        if cands is not None:
            for cand in cands:
                if _containslc(line, end, cand, end):
                    key = cand
                    break

        if key is None:
            if not all_headers:
                continue
            key = _normalize_key(line, 0, end)
            if key is None:
                continue
            if not isinstance(key, bytes):
                key = bytes(key)
        elif key == _SET_COOKIE and not and_cookies:
            continue

        start, end = sep + 1, len(line)
        while start < end and line[start] <= 32: start += 1
        while end > start and line[end - 1] <= 32: end -= 1
        _append(key)
        _append(line[start:end])

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
        except Exception as e:
            try: sock.close()
            except (AttributeError, OSError): pass
            raise e
    if err is not None:
        raise err
    raise OSError(errno.EHOSTUNREACH)

# Streaming response supporting Content-Length, chunked, and read-to-EOF framing.
class HTTPResponse:
    blocksize = 2048

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        return False

    def __init__(self, sock, method=None, url=None):
        self._sock = sock
        self._have_recv_into = hasattr(sock, "recv_into")
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
        self._blocking = True

    # Read the status line and headers, then work out body framing and keep-alive.
    def begin(self, *, all_headers=False, and_cookies=None):
        if self._headers is not None:
            return
        self._require_blocking()
        self.version, self.status, self.reason = self._read_status()
        if _DEBUG:
            print("status:", repr(self.version), repr(self.status), repr(self.reason))

        self._headers = parse_headers(self._sock, all_headers=all_headers, and_cookies=and_cookies)
        if _DEBUG:
            for i in range(0, len(self._headers), 2):
                print("header:", repr(self._headers[i]), "=", repr(self._headers[i+1]))

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

        self.chunked = bool(transfer_encoding) and bool(_containslc(transfer_encoding, len(transfer_encoding), b"chunked", 7))
        self.chunk_left = None

        if self.version == 10:
            self.will_close = (not connection) or not bool(_containslc(connection, len(connection), b"keep-alive", 10))
        else:
            self.will_close = bool(connection) and bool(_containslc(connection, len(connection), b"close", 5))

        self.length = None
        if content_length and not self.chunked:
            try:
                self.length = int(content_length, 10)
                if self.length < 0:
                    self.length = None
            except ValueError:
                pass
        self._bytes_read = 0

        # These responses never carry a body.
        if (100 <= self.status < 200
            or self.status == 204 or self.status == 304
            or self._method == b"HEAD"):
            self.chunked = False
            self.length = 0

        # No framing info: body ends only when the server closes the connection.
        if self.length is None and not self.chunked:
            self.will_close = True

    def _close(self, sock):
        self._sock = None
        try: sock.close()
        except (AttributeError, OSError): pass

    # Release the socket; hard-close it only if it can't be safely reused.
    # tainted=True marks the stream corrupt and raises IncompleteRead.
    def close(self, tainted=False):
        sock = self._sock
        if tainted:
            self._close(sock)
            raise IncompleteRead(self._bytes_read, self.length)
        if sock is not None:
            self._sock = None
            if (self.will_close or self.chunked
                    or (self.length is not None and self._bytes_read < self.length)):
                try: sock.close()
                except OSError: pass

    def isclosed(self):
        return self._sock is None

    def _require_nonchunked(self):
        if self.chunked:
            raise ValueError("operation requires a non-chunked stream")

    def _require_blocking(self):
        if not self._blocking:
            raise ValueError("operation requires a blocking socket")

    # Switch to non-blocking reads (recv/recv_into). One-way; disables socket reuse.
    def setblocking(self, flag):
        if flag:
            raise ValueError("can only transition to non-blocking")
        self._require_nonchunked()
        try: self._sock.setblocking(False)
        except AttributeError: pass
        self._blocking = False
        self.will_close = True

    def _readline(self):
        sock = self._sock
        if sock is None:
            return None
        try:
            return sock.readline()
        except OSError:
            self._close(sock)
            raise

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

    # Advance chunked framing: consume size lines, inter-chunk CRLFs and the
    # trailer as needed; return bytes left in the current chunk (0 = end of body).
    def _next_chunk(self):
        while True:
            if self.chunk_left is None:
                line = self._readline()
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
                    line = self._readline()
                    if line == _CRLF or line == _LF:
                        self.chunked = False
                        self.length = self._bytes_read
                        self.close()
                        return 0
                    if not line:
                        self.close(True)
            elif self.chunk_left == 0:
                line = self._readline()
                if line != _CRLF and line != _LF:
                    self.close(True)
                self.chunk_left = None
            else:
                return self.chunk_left

    # Read up to amt bytes, or the entire remaining body if amt is None/negative.
    def read(self, amt=None):
        self._require_blocking()
        sock = self._sock
        if sock is None:
            return _BLANK

        unbounded = amt is None or amt < 0
        if unbounded and self.length is None and not self.chunked:
            try:
                data = sock.read()
            except OSError:
                self._close(sock)
                raise
            if not data:
                self.close()
                return _BLANK
            self._bytes_read += len(data)
            self.close()
            return data

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
            try:
                data = sock.read(amt)
            except OSError:
                self._close(sock)
                raise
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
            try:
                chunk = sock.read(want)
            except OSError:
                self._close(sock)
                raise
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

    # Single recv-style read: at most one chunk/blocksize of data, possibly short.
    def readshort(self, amt=None):
        self._require_blocking()
        sock = self._sock
        if sock is None:
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
        try:
            data = sock.read(amt)
        except OSError:
            self._close(sock)
            raise
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

    # Fill buf as far as the body allows; returns bytes written (0 = end of body).
    def readinto(self, buf):
        self._require_blocking()
        sock = self._sock
        if sock is None or not buf:
            return 0

        if not self.chunked:
            if self.length is None:
                amt = len(buf)
            else:
                amt = min(len(buf), self.length - self._bytes_read)
                if amt == 0:
                    self.close()
                    return 0
            try:
                n = sock.readinto(buf, amt)
            except OSError:
                self._close(sock)
                raise
            if not n:
                self.close(self.length is not None)
                return 0
            self._bytes_read += n
            if self.length is not None and self._bytes_read >= self.length:
                self.close()
            return n

        len_buf = len(buf)
        if isinstance(buf, memoryview):
            bmv = buf
        else:
            bmv = memoryview(buf)

        total = 0
        while total < len_buf:
            amt = min(self._next_chunk(), len_buf - total)
            if amt == 0:
                break
            try:
                if total == 0:
                    n = sock.readinto(buf, amt)
                else:
                    n = sock.readinto(bmv[total:], amt)
            except OSError:
                self._close(sock)
                raise
            if not n:
                self.close(True)
            self._bytes_read += n
            self.chunk_left -= n
            total += n
        return total

    # Non-blocking-friendly read: None while no data is available yet, b"" at end of body.
    def recv(self, amt=None):
        self._require_nonchunked()
        sock = self._sock
        if sock is None:
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
            data = sock.recv(amt)
        except OSError as e:
            if e.errno == errno.EAGAIN:
                return None
            self._close(sock)
            raise
        if data is None:
            return None

        if not data:
            self.close(self.length is not None)
            return _BLANK
        n = len(data)
        self._bytes_read += n
        if self.length is not None and self._bytes_read >= self.length:
            self.close()
        return data

    # Non-blocking-friendly readinto: None while no data is available yet, 0 at end of body.
    def recv_into(self, buf):
        self._require_nonchunked()
        sock = self._sock
        if sock is None or not buf:
            return 0

        if self.length is None:
            amt = len(buf)
        else:
            amt = min(len(buf), self.length - self._bytes_read)
            if amt == 0:
                self.close()
                return 0

        if self._blocking and not self._have_recv_into:
            data = self.recv(min(amt, self.blocksize))
            if data is None:
                return None
            n = len(data)
            if n:
                buf[:n] = data
            return n

        try:
            if self._have_recv_into:
                n = sock.recv_into(buf, amt)
            else:
                n = sock.readinto(buf, amt)
        except OSError as e:
            if e.errno == errno.EAGAIN:
                return None
            self._close(sock)
            raise
        if n is None:
            return None

        if n == 0:
            self.close(self.length is not None)
            return 0
        self._bytes_read += n
        if self.length is not None and self._bytes_read >= self.length:
            self.close()
        return n

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
        _readinto = self.readinto
        while True:
            n = _readinto(bmv)
            if n == 0:
                return
            yield n

    # Decoded (str, str) header pairs; entries that fail Latin-1 decoding are dropped.
    def getheaders(self):
        out = []
        for key, val in self.rawheaders():
            try:
                out.append((decode_latin1(key), decode_latin1(val)))
            except UnicodeError:
                pass
        return out

    def rawheaders(self):
        if self._headers is None:
            raise ResponseNotReady()
        for i in range(0, len(self._headers), 2):
            yield self._headers[i], self._headers[i+1]

    def getheader(self, key, default=None):
        return decode_latin1(self.rawheader(key, None), default)

    # Raw value for key; repeated headers are joined with ", " per RFC 9110.
    def rawheader(self, key, default=None):
        if self._headers is None:
            raise ResponseNotReady()
        key = _normalize_key(key)
        if key is None:
            raise ValueError("invalid key")
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
        return decode_latin1(self.rawcookie(name, None), default)

    # Extract a cookie's raw value from Set-Cookie headers, stripping quotes.
    # (59/61/34 are ";", "=" and '"'.)
    def rawcookie(self, name, default=None):
        len_name = len(name)
        for key, val in self.rawheaders():
            if key != _SET_COOKIE:
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

# http.client.HTTPConnection work-alike with small-write coalescing and
# transparent reconnection of idle keep-alive sockets.
class HTTPConnection:
    response_class = HTTPResponse
    default_port = HTTP_PORT
    auto_open = True
    blocksize = 2048
    # Coalesce request line + headers into roughly one TCP segment.
    _merge_buffer_size = 1460

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        return False

    def __init__(self, host, port=None, timeout=_DEFAULT_TIMEOUT, network=None):
        self.timeout = timeout
        self._sock = None
        self._merge_buffer = None
        self._merge_buffmv = None
        self._merged = 0
        self.__response = None
        self._method = None
        self._url = None
        self._set_host(host, port)
        self._network = network
        self._can_reconnect = False

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

    def _require_network(self):
        if self._network is not None and not self._network.connect():
            raise NotConnected("network unavailable")

    def connect(self):
        self._require_network()
        self._sock = create_connection((self._hostaddr, self.port), self.timeout)

    # Drop buffers, any pending response, and the socket.
    def close(self):
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
            except (AttributeError, OSError): pass

    # Convenience wrapper: send request line, headers and body in one call.
    def request(self, method, url, body=None, headers=None, *, encode_chunked=None):
        have_accept_encoding = False
        have_content_length = False
        have_host = False
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
            for key, value in pairs:
                key = _normalize_key(key, lower=False)
                if key is None:
                    raise ValueError("invalid key")
                headers.append((key, value))
                len_key = len(key)
                if len_key == 4:
                    if _containslc(key, 4, b"host", 4):
                        have_host = True
                elif len_key == 14:
                    if _containslc(key, 14, b"content-length", 14):
                        have_content_length = True
                elif len_key == 15:
                    if _containslc(key, 15, b"accept-encoding", 15):
                        have_accept_encoding = True
                elif len_key == 17:
                    if _containslc(key, 17, b"transfer-encoding", 17):
                        have_transfer_encoding = True
            del pairs
        else:
            headers = []

        self.putrequest(method, url, skip_accept_encoding=have_accept_encoding, skip_host=have_host)

        if isinstance(body, str):
            body = body.encode()

        # Infer framing: known-length bodies get Content-Length, streams get chunked.
        if encode_chunked is None:
            if body is None:
                encode_chunked = False
                if not have_content_length and self._method in _METHODS_EXPECTING_BODY:
                    headers.append((b"Content-Length", b"0"))
            elif isinstance(body, (bytes, bytearray, memoryview)):
                encode_chunked = False
                if not have_content_length:
                    headers.append((b"Content-Length", b"%d" % len(body)))
            else:
                encode_chunked = not have_content_length
        if encode_chunked and not have_transfer_encoding:
            headers.append((b"Transfer-Encoding", b"chunked"))

        for key, value in headers:
            self.putheader(key, value)

        self.endheaders(body, encode_chunked=encode_chunked)

    # Start a request: send the request line plus default Host and
    # Accept-Encoding headers (suppressed if the caller provides their own).
    def putrequest(self, method, url, skip_host=False, skip_accept_encoding=False):
        if (self._method is not None and self._sock is not None
                and (self.__response is None or not self.__response.isclosed())):
            raise CannotSendRequest()
        self.__response = None

        self._can_reconnect = self.auto_open
        self._merged = 0

        method = _encode_and_validate(method, 1)
        if not isinstance(method, bytes):
            method = bytes(method)

        url = _encode_and_validate(url, 1)
        if not isinstance(url, bytes):
            url = bytes(url)
        if not url:
            url = b"/"

        self._method = method
        self._url = url
        self._putheaderparts(False, method, b" ", url, b" HTTP/1.1\r\n")

        if not skip_host:
            self._putheaderparts(False, b"Host: ", self._hostport, _CRLF)
        if not skip_accept_encoding:
            self._putheaderparts(False, b"Accept-Encoding: identity\r\n")

    def putheader(self, key, val):
        if self.__response is not None or self._method is None:
            raise CannotSendHeader()
        if isinstance(key, str):
            key = key.encode()
        val = _encode_and_validate(val, 0)
        self._putheaderparts(False, key, b": ", val, _CRLF)

    # Send a Cookie header; the value is quoted unless it already contains quotes.
    def putcookie(self, name, value):
        if self.__response is not None or self._method is None:
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
            self._putheaderparts(False, b"Cookie: ", name, b'="', value, b'"', _CRLF)

    # Append parts to the merge buffer, flushing to the socket as it fills
    # (or unconditionally when flush=True).
    def _putheaderparts(self, flush, *parts):
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

    # Terminate the header block with a blank line and optionally send the body.
    def endheaders(self, message_body=None, *, encode_chunked=False):
        if self.__response is not None or self._method is None:
            raise CannotSendHeader()
        self._putheaderparts(True, _CRLF)
        if message_body is not None or encode_chunked:
            self.send(message_body, encode_chunked=encode_chunked)

    # Write to the socket, reconnecting once if an idle keep-alive
    # connection turns out to have been dropped by the server.
    def _send_raw(self, data):
        if not data:
            return
        if _DEBUG:
            print("send:", len(data), "bytes")

        self._require_network()

        if self._can_reconnect:
            if self._sock is not None:
                try:
                    self._sock.sendall(data)
                    self._can_reconnect = False
                    return
                except OSError:
                    try: self._sock.close()
                    except (AttributeError, OSError): pass
                self._sock = None
            try:
                self.connect()
                self._sock.sendall(data)
            except OSError as e:
                if self._sock is not None:
                    try: self._sock.close()
                    except (AttributeError, OSError): pass
                    finally: self._sock = None
                raise NotConnected(str(e))
            self._can_reconnect = False
            return

        if self._sock is None:
            raise NotConnected("socket missing")
        self._sock.sendall(data)
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

    # Send a body: bytes-like, str, a stream with readinto(), or an iterable of chunks.
    def send(self, data, *, encode_chunked=False, final_chunk=True):
        if self.__response is not None:
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

    # Read the response to the last request. The socket is kept for reuse
    # unless the response framing requires closing it.
    def getresponse(self, **kwargs):
        if (self.__response is not None
            or self._method is None
            or self._sock is None
            or self._can_reconnect
            or self._merged):
            raise ResponseNotReady()
        response = None
        try:
            response = self.response_class(self._sock, self._method, self._url)
            response.begin(**kwargs)
            if response.will_close:
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
                except (AttributeError, OSError): pass
            raise
        finally:
            # Help small heaps: header parsing fragments memory.
            if _GC_THRESHOLD and gc.mem_free() < _GC_THRESHOLD:
                gc.collect()

    # Hand over the underlying socket (e.g. after a 101 upgrade) and reset.
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
    # TLS variant. NOTE: certificate verification is OFF by default;
    # pass an ssl context to enable it.
    class HTTPSConnection(HTTPConnection):
        default_port = HTTPS_PORT
        blocksize = 2048
        _merge_buffer_size = 1024

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
                    except (AttributeError, OSError): pass
                if isinstance(e, OSError):
                    raise e
                elif isinstance(e, MemoryError):
                    raise OSError(errno.ENOMEM)
                else:
                    raise OSError(errno.EIO)
