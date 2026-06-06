# http/client_ish.py

import micropython, socket, errno, gc

HTTP_PORT = const(80)
HTTPS_PORT = const(443)

# Memory threshold below which GC is called after a request
_GC_THRESHOLD = const(32768)

# Headers to always retain when parse_headers() filters
_IMPORTANT_HEADERS = (
    b"connection",
    b"content-encoding",
    b"content-length",
    b"content-type",
    b"etag",
    b"keep-alive",
    b"location",
    b"retry-after",
    b"transfer-encoding",
    b"www-authenticate",
)

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
def _lower(buf:ptr8, buflen:int, do_lower:int) -> int:
    i = 0
    while i < buflen:
        b = buf[i]
        if (65 <= b and b <= 90):
            if not do_lower:
                return 0
            buf[i] = b + 32
        i += 1
    return 1

def _normalize_key(key):
    if isinstance(key, str):
        key = key.encode()
    elif not isinstance(key, (bytes, bytearray, memoryview)):
        key = str(key).encode()
    len_key = len(key)
    if len_key and (key[0] <= 32 or key[-1] <= 32):
        if isinstance(key, memoryview):
            key = bytes(key)
        key = key.strip()
        len_key = len(key)
    if not _lower(key, len_key, False):
        if not isinstance(key, bytearray):
            key = bytearray(key)
        _lower(key, len_key, True)
    return key

@micropython.viper
def _validate_ascii(buf:ptr8, buflen:int, no_space:int) -> int:
    i = 0
    while i < buflen:
        b = buf[i]
        if b < 9 or (b == 9 and no_space) or (9 < b and b < 32) or (b == 32 and no_space) or b >= 127:
            return 0
        i += 1
    return 1

def _encode_and_validate(val, force_bytes, no_space):
    if isinstance(val, str):
        val = val.encode()
    elif not isinstance(val, (bytes, bytearray, memoryview)):
        val = str(val).encode()
    if not _validate_ascii(val, len(val), no_space):
        raise ValueError("can't contain special characters")
    if force_bytes and not isinstance(val, bytes):
        val = bytes(val)
    return val

def create_connection(address, timeout=None):
    host, port = address
    for f, t, p, n, a in socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM):
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
        except Exception as e:
            if sock is not None:
                try: sock.close()
                except OSError: pass
            if not isinstance(e, OSError):
                raise e
    raise OSError(errno.EHOSTUNREACH)

def parse_headers(sock, *, extra_headers=True):
    # Returns [lowercase_key_bytes, value_bytes, ...]. extra_headers:
    #   None       -> skip all headers
    #   True       -> keep all headers
    #   Falsy      -> keep _IMPORTANT_HEADERS only
    #   container  -> keep _IMPORTANT_HEADERS plus those in container
    headers = []
    _append = headers.append
    _readline = sock.readline
    while True:
        line = _readline()
        if not line or line == _CRLF or line == b"\n":
            return headers
        if extra_headers is None:
            continue
        # Folded continuations (RFC 7230 deprecated) are dropped.
        if line[0] <= 32:
            continue
        sep = line.find(b":")
        if sep == -1:
            continue
        key, val = line[:sep], line[sep+1:]
        key = _normalize_key(key)
        if extra_headers is True or (extra_headers and key in extra_headers) or key in _IMPORTANT_HEADERS:
            if not isinstance(key, bytes):
                key = bytes(key)
            val = val.strip()
            _append(key)
            _append(val)

class HTTPResponse:
    blocksize = const(2048)

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
        self.headers = None
        self.version = None
        self.status = None
        self.reason = None
        self.chunked = False
        self.chunk_left = None
        self.length = None
        self.will_close = True
        self._bytes_read = 0
        # Set by readers on protocol violation or premature EOF; forces
        # the socket closed even if response would otherwise keep-alive.
        self._tainted = False

    def begin(self, *, extra_headers=True):
        self.version, self.status, self.reason = self._read_status()
        if self.debuglevel > 0:
            print("status:", repr(self.version), repr(self.status), repr(self.reason))

        self.headers = parse_headers(self._sock, extra_headers=extra_headers)
        if self.debuglevel > 0:
            for key, val in self.headers:
                print("header:", repr(key), "=", repr(val))

        transfer_encoding = self._getheaderbytesfast(b"transfer-encoding", b"")
        self.chunked = bool(transfer_encoding) and b"chunked" in transfer_encoding
        self.chunk_left = None

        conn = self._getheaderbytesfast(b"connection", b"")
        if self.version == 10:
            self.will_close = (not conn) or b"keep-alive" not in conn.lower()
        else:
            self.will_close = bool(conn) and b"close" in conn.lower()

        # Content-Length ignored when chunked.
        self.length = None
        length = self._getheaderbytesfast(b"content-length")
        if length and not self.chunked:
            try:
                self.length = int(length, 10)
                if self.length < 0:
                    self.length = None
            except ValueError:
                pass
        self._bytes_read = 0

        # Responses defined to never have a body.
        if (100 <= self.status < 200
            or self.status == 204 or self.status == 304
            or self._method == b"HEAD"):
            self.length = 0
            self.chunked = False
            self.chunk_left = None

        # Unknown framing -> body is delimited by close.
        if self.length is None and not self.chunked:
            self.will_close = True

    def _read_status(self):
        while True:
            line = self._sock.readline()
            if self.debuglevel > 0:
                print("status:", repr(line))
            if not line:
                raise RemoteDisconnected()
            if not line.startswith(b"HTTP/") or not line.endswith(b"\n"):
                raise BadStatusLine()

            line = line.split(None, 2)
            if len(line) == 3:
                version, status, reason = line  # caller should rstrip reason
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
                if not line or line == _CRLF or line == b"\n":
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

    def close(self, _tainted=False):
        # _tainted ALWAYS raises IncompleteRead after closing the socket.
        # Reader code in _next_chunk/_readinto_chunked relies on this for
        # control flow; do not break this contract.
        if _tainted:
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
        if _tainted:
            raise IncompleteRead(self._bytes_read, self.length)

    def isclosed(self):
        return self._sock is None

    def read(self, amt=None):
        if amt is None:
            return self._read_all()
        amt = int(amt)
        if amt < 0:
            return self._read_all()
        if self.length is not None:
            amt = min(amt, self.length - self._bytes_read)
        if amt == 0:
            return _BLANK
        buf = bytearray(amt)
        n = self.readinto(buf)
        if n == 0:
            return _BLANK
        if n < amt:
            del buf[n:]
        return buf

    def _read_all(self):
        if self.chunked:
            buflen = self.blocksize
            buf = bytearray(buflen)
            bmv = memoryview(buf)
            out = bytearray()
            while True:
                n = self._readinto_chunked(bmv)
                if n == 0:
                    return out
                if n == buflen:
                    out.extend(buf)
                else:
                    out.extend(bmv[:n])
        if self.length is not None:
            amt = self.length - self._bytes_read
            if amt == 0:
                return _BLANK
            buf = bytearray(amt)
            n = self._readinto_raw(buf)
            if n < amt:
                del buf[n:]
            return buf
        # Length unknown, not chunked: read until close.
        if not self.isclosed():
            try:
                buf = self._sock.read()
            finally:
                self.close()
            if buf is not None:
                self._bytes_read += len(buf)
                return buf
        return _BLANK

    def readinto(self, buf):
        if self.chunked:
            return self._readinto_chunked(buf)
        else:
            return self._readinto_raw(buf)

    def _readinto_chunked(self, buf):
        buflen = len(buf)
        if buflen == 0 or self.isclosed():
            return 0
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
            if n == 0:
                self.close(True)  # raises
            self._bytes_read += n
            self.chunk_left -= n
            total += n
        return total

    def _next_chunk(self):
        # Advances the chunk state machine. Returns bytes available in
        # the current data chunk, or 0 at the end of the body.
        # .close(True) sites below transfer control via IncompleteRead.
        while True:
            if self.chunk_left is None:
                line = self._sock.readline()
                if not line:
                    self.close(True)  # raises
                sep = line.find(b";")
                if sep >= 0:
                    line = line[:sep]
                try:
                    size = int(line, 16)
                except ValueError:
                    size = -1
                if size < 0:
                    self.close(True)  # raises
                self.chunk_left = size
                if size == 0:
                    # Drain trailers; clean exit if blank line, taint on EOF.
                    while True:
                        line = self._sock.readline()
                        if not line or line == _CRLF or line == b"\n":
                            self.chunk_left = None
                            self.close(not line)
                            return 0
            elif self.chunk_left == 0:
                # Consume CRLF terminating the previous data chunk.
                line = self._sock.readline()
                if line != _CRLF and line != b"\n":
                    self.close(True)  # raises
                self.chunk_left = None
            else:
                return self.chunk_left

    def _readinto_raw(self, buf):
        buflen = len(buf)
        if buflen == 0 or self.isclosed():
            return 0

        if self.length is None:
            amt = buflen
        else:
            amt = min(buflen, self.length - self._bytes_read)
            if amt == 0:
                self.close()
                return 0

        n = self._sock.readinto(buf, amt)
        if n == 0:
            # EOF: taint only if we expected more bytes.
            self.close(self.length is not None)
            return 0
        self._bytes_read += n
        if self.length is not None and self._bytes_read >= self.length:
            self.close()
        return n

    def getheaders(self):
        if self.headers is None:
            raise ResponseNotReady()
        out = []
        for i in range(0, len(self.headers), 2):
            try:
                out.append((self.headers[i].decode(), self.headers[i+1].decode()))
            except UnicodeError:
                pass
        return out

    def getheader(self, key, default=None):
        val = self.getheaderbytes(key)
        if val is not None:
            try:
                return val.decode()
            except UnicodeError:
                pass
        return default

    def getheaderbytes(self, key, default=None):
        if self.headers is None:
            raise ResponseNotReady()
        key = _normalize_key(key)
        match = None
        for i in range(0, len(self.headers), 2):
            if self.headers[i] == key:
                v = self.headers[i+1]
                if match is None:
                    match = v
                else:
                    match = b", ".join((match, v)) 
        return default if match is None else match

    def _getheaderbytesfast(self, key, default=None):
        for i in range(0, len(self.headers), 2):
            if self.headers[i] == key:
                return self.headers[i+1]
        return default

    def getcookies(self):
        out = []
        for v in self.getcookiesbytes():
            try:
                out.append(v.decode())
            except UnicodeError:
                pass
        return out

    def getcookiesbytes(self):
        if self.headers is None:
            raise ResponseNotReady()
        for i in range(0, len(self.headers), 2):
            if self.headers[i] == b"set-cookie":
                yield self.headers[i+1]

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
        while True:
            n = self.readinto(bmv)
            if n == 0:
                return
            yield n

class HTTPConnection:
    response_class = HTTPResponse
    default_port = HTTP_PORT
    auto_open = True
    blocksize = const(2048)
    _merge_buffer_size = const(2048)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        return False

    def __init__(self, host, port=None, timeout=None):
        self.debuglevel = 0
        self.timeout = timeout
        self._sock = None
        if self._merge_buffer_size:
            self._merge_buffmv = memoryview(bytearray(self._merge_buffer_size))
        else:
            self._merge_buffmv = None
        self._merged = 0
        self.__response = None
        self._method = None
        self._url = None
        self.host, self.port = self._parse_host_port(host, port)
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
        response = self.__response
        self.__response = None
        if response is not None:
            response._sock = None
        sock = self._sock
        self._sock = None
        if sock is not None:
            try: sock.close()
            except OSError: pass

    def _parse_host_port(self, host, port):
        parsed_port = None
        if host.startswith("["):
            close = host.rfind("]")
            if close == -1:
                raise ValueError("invalid host")
            host, rest = host[1:close], host[close+1:]
            if rest.startswith(":"):
                if len(rest) > 1:
                    parsed_port = rest[1:]
            elif rest:
                raise ValueError("invalid host")
        elif host.count(":") == 1:
            host, parsed_port = host.rsplit(":", 1)
        if port is None:
            port = parsed_port
        if not host:
            raise ValueError("invalid host")
        if port is None or port == "":
            port = self.default_port
        if isinstance(port, str):
            try:
                port = int(port, 10)
            except ValueError:
                port = -1
        if isinstance(port, int) and not (0 <= port <= 65535):
            raise ValueError("invalid port")
        return (host, port)

    def request(self, method, url, body=None, headers=None, *, encode_chunked=None):
        have_accept_encoding = False
        have_content_length = False
        have_host = False
        have_transfer_encoding = False

        if headers is not None:
            is_dict = isinstance(headers, dict)
            if not is_dict and not isinstance(headers, (list, tuple)):
                headers = list(headers) # Materialize generator/iterator
            for key in headers:
                if not is_dict:
                    key = key[0]
                key = _normalize_key(key)
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

        if headers is not None:
            for item in headers:
                if is_dict:
                    self.putheader(item, headers[item])
                else:
                    self.putheader(item[0], item[1])

        self.endheaders(body, encode_chunked=encode_chunked)

    def putrequest(self, method, url, skip_host=False, skip_accept_encoding=False):
        if self.__response is not None and not self.__response.isclosed():
            raise CannotSendRequest()
        self.__response = None

        self._can_reconnect = self.auto_open
        self._merged = 0

        method = _encode_and_validate(method, True, 1)
        if method != b"GET":
            method = method.upper()

        if url is not None:
            url = _encode_and_validate(url, True, 1) or b"/"
        else:
            url = b"/"

        self._method = method
        self._url = url
        self._putheaderparts(False, method, b" ", url, b" HTTP/1.1\r\n")

        if not skip_host:
            host = self.host.encode()
            if b":" in host and not host.startswith(b"["):
                host = b"[" + host + b"]"
            if self.port == self.default_port:
                self.putheader(b"Host", host)
            else:
                self.putheader(b"Host", b"%s:%d" % (host, self.port))
        if not skip_accept_encoding:
            self._putheaderparts(False, b"Accept-Encoding: identity\r\n")

    def putheader(self, header, value):
        if self.__response is not None:
            raise CannotSendHeader()
        if isinstance(header, str):
            header = header.encode()
        self._putheaderparts(False, header, b": ", _encode_and_validate(value, False, 0), _CRLF)

    def _putheaderparts(self, flush, *parts):
        # Coalesces small writes into a single sendall.
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
                self._merge_buffmv[self._merged:self._merged+len_part] = part
                self._merged += len_part
            else:
                self._send_raw(self._merge_buffmv[:self._merged])
                self._merge_buffmv[:len_part] = part
                self._merged = len_part

        if flush and self._merged:
            self._send_raw(self._merge_buffmv[:self._merged])
            self._merged = 0

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
        if self._merge_buffmv is not None and self._merged == 0:
            len_header = len(header)
            total_len = len_header + len_data + 2
            if total_len <= self._merge_buffer_size:
                self._merge_buffmv[:len_header] = header
                self._merge_buffmv[len_header:len_header+len_data] = data
                self._merge_buffmv[len_header+len_data:total_len] = _CRLF
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
                if n == 0:
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
        return sock

try:
    import ssl
except ImportError:
    pass
else:
    class HTTPSConnection(HTTPConnection):
        default_port = const(HTTPS_PORT)
        blocksize = const(1200)
        _merge_buffer_size = const(1200)

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
            omit_sni = ":" in self.host or all(c.isdigit() or c == "." for c in self.host)
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
