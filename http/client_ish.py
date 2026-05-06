# http/client_ish.py

import micropython, socket, errno

HTTP_PORT = const(80)
HTTPS_PORT = const(443)

# Headers always retained when parse_headers is asked to filter.
_IMPORTANT_HEADERS = frozenset((
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
))

# MicroPython lacks iso-8859-1; use utf-8 throughout.
_DECODE_HEAD = const("utf-8")
_ENCODE_HEAD = const("utf-8")
_DECODE_BODY = const("utf-8")
_ENCODE_BODY = const("utf-8")

_BLANK = const(b"")
_CRLF = const(b"\r\n")

class HTTPException(Exception): pass
class NotConnected(HTTPException): pass
class BadStatusLine(HTTPException): pass
class RemoteDisconnected(BadStatusLine): pass
class ImproperConnectionState(HTTPException): pass
class CannotSendRequest(ImproperConnectionState): pass
class CannotSendHeader(ImproperConnectionState): pass
class ResponseNotReady(ImproperConnectionState): pass
class IncompleteRead(HTTPException):
    def __init__(self, bytes_read, content_length):
        self.args = (bytes_read, content_length)
    def __repr__(self):
        return "IncompleteRead(%s, %s)" % (self.args[0], self.args[1])
    def __str__(self):
        return self.__repr__()

@micropython.viper
def _lower(buf:ptr8, buflen:int, inplace:bool) -> int:
    # inplace=False: returns 1 if already lowercase, 0 otherwise (no writes).
    # inplace=True:  lowercases in place, always returns 1.
    i = 0
    while i < buflen:
        b = buf[i]
        if 65 <= b <= 90:
            if inplace:
                buf[i] = b + 32
            else:
                return 0
        i += 1
    return 1

@micropython.viper
def _validate_ascii(buf:ptr8, buflen:int, deny_flags:int) -> int:
    # Returns 1 if valid, 0 if rejected. Always rejects ctrl chars and
    # bytes >= 127. deny_flags bit 0 additionally rejects space.
    deny_space = (deny_flags & 1)
    i = 0
    while i < buflen:
        b = buf[i]
        if b < 32 or b >= 127:
            return 0
        if b == 32 and deny_space:
            return 0
        i += 1
    return 1

def _encode_and_validate(b, charset, deny_flags):
    if isinstance(b, (bytes, bytearray)):
        pass
    elif isinstance(b, str):
        b = b.encode(charset)
    else:
        raise TypeError("must be bytes-like")
    if _validate_ascii(b, len(b), deny_flags) == 0:
        raise ValueError("can't contain special characters")
    return b

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
                try:
                    sock.close()
                except OSError:
                    pass
            if not isinstance(e, OSError):
                raise e
    raise OSError(errno.EHOSTUNREACH)

def _normalize_key(key):
    # Strip surrounding whitespace, lowercase, return immutable bytes.
    if isinstance(key, str):
        key = key.encode(_ENCODE_HEAD)
    len_key = len(key)
    if len_key and (key[0] <= 32 or key[-1] <= 32):
        key = key.strip()
        len_key = len(key)
    if not _lower(key, len_key, False):
        if not isinstance(key, bytearray):
            key = bytearray(key)
        _lower(key, len_key, True)
    if not isinstance(key, bytes):
        key = bytes(key)
    return key

def parse_headers(sock, *, extra_headers=True):
    # Returns [(lowercase_key_bytes, value_bytes), ...]. extra_headers:
    #   True       -> keep all headers
    #   False/None -> keep only _IMPORTANT_HEADERS
    #   container  -> keep _IMPORTANT_HEADERS plus those in container
    headers = []
    while True:
        line = sock.readline()
        if not line or line == _CRLF or line == b"\n":
            return headers
        # Folded continuations (RFC 7230 deprecated) are dropped, not appended.
        if line[0] <= 32:
            continue
        sep = line.find(b':')
        if sep == -1:
            continue
        key, val = line[:sep], line[sep+1:]
        key = _normalize_key(key)
        if extra_headers is True or (extra_headers and key in extra_headers) or key in _IMPORTANT_HEADERS:
            headers.append((key, val.strip()))

class HTTPResponse:
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
        self.version = None
        self.status = None
        self.reason = None
        self.headers = None
        self.chunked = False
        self.chunk_left = None
        self.will_close = True
        self.length = None
        self._bytes_read = 0
        # Set when readers detect protocol violation or premature EOF; forces
        # the socket closed even if the response would otherwise keep-alive.
        self._tainted = False

    def begin(self, *, extra_headers=True):
        self.version, self.status, self.reason = self._read_status()
        if self.debuglevel > 0:
            print("status:", repr(self.version), repr(self.status), repr(self.reason))

        self.headers = parse_headers(self._sock, extra_headers=extra_headers)
        if self.debuglevel > 0:
            for key, val in self.headers:
                print("header:", repr(key), "=", repr(val))

        transfer_encoding = self._getheader_bytes(b"transfer-encoding", b"")
        self.chunked = (b"chunked" in transfer_encoding.lower())
        self.chunk_left = None

        conn = self._getheader_bytes(b"connection", b"").lower()
        if self.version == 10:
            self.will_close = b"keep-alive" not in conn
        else:
            self.will_close = b"close" in conn

        # Content-Length is ignored when chunked (RFC 7230 S3.3.3).
        self.length = None
        length = self._getheader_bytes(b"content-length", None)
        if length and not self.chunked:
            try:
                self.length = int(length, 10)
            except ValueError:
                pass
            else:
                if self.length < 0:
                    self.length = None
        self._bytes_read = 0

        # Responses defined by RFC to never have a body.
        if (100 <= self.status < 200
            or self.status == 204 or self.status == 304
            or self._method == b"HEAD"):
            self.length = 0
            self.chunked = False
            self.chunk_left = None

        # Unknown framing on a keep-alive connection -> must close to delimit body.
        if self.length is None and not self.chunked:
            self.will_close = True

    def _read_status(self):
        while True:
            line = self._sock.readline()
            if self.debuglevel > 0:
                print("status:", repr(line))
            if not line:
                # Half-closed keep-alive between requests; caller may retry.
                raise RemoteDisconnected()
            if not line.startswith(b"HTTP/") or not line.endswith(b'\n'):
                raise BadStatusLine()

            line = line.split(None, 2)
            if len(line) == 3:
                version, status, reason = line
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

            if status != 100:
                break
            # Skip 100 Continue's header block and re-read the real status.
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

    def close(self, tainted=False):
        # Quiet by default. With tainted=True, raises IncompleteRead after
        # closing the socket; readers use this to signal protocol violations
        # or premature EOF from the read site.
        if tainted:
            self._tainted = True
        sock = self._sock
        self._sock = None
        if sock is not None:
            framing_incomplete = (
                self.chunk_left is not None
                or (self.length is not None and self._bytes_read < self.length)
            )
            # Close the socket if we can't safely reuse it; otherwise leave it
            # open for HTTPConnection to keep-alive.
            if self._tainted or framing_incomplete or self.will_close:
                try:
                    sock.close()
                except OSError:
                    pass
        if tainted:
            raise IncompleteRead(self._bytes_read, self.length)

    def isclosed(self):
        return self._sock is None

    def readinto(self, buf):
        if isinstance(buf, memoryview):
            return self._readinto(buf)
        else:
            return self._readinto(memoryview(buf))

    def _readinto(self, bmv):
        if len(bmv) == 0:
            return 0
        if self.chunked:
            return self._read_chunked(bmv)
        else:
            return self._read_raw(bmv)

    def read(self, amt=None):
        if amt == 0:
            return _BLANK
        if not self.chunked:
            chunk = self._read_raw(amt)
            return _BLANK if chunk is None else chunk
        parts = self._read_chunked(amt)
        if not parts:
            return _BLANK
        if len(parts) == 1:
            return parts[0]
        return _BLANK.join(parts)

    def _read_chunked(self, arg=None):
        # Blocking socket assumed. arg modes:
        #   memoryview -> fill it, return int bytes-written
        #   None       -> drain to terminator, return list[bytes]
        #   int        -> read up to that many, return list[bytes]
        # Negative ints are coerced to None. Zero is filtered upstream.
        arg_is_memoryview = isinstance(arg, memoryview)
        if arg_is_memoryview:
            res = arg
        else:
            parts = []
            if arg is not None:
                arg = int(arg)
                if arg < 0:
                    arg = None
        total = 0

        while True:
            if self.isclosed():
                break

            if self.chunk_left is None:
                line = self._sock.readline()
                if not line:
                    self.close(True)
                sep = line.find(b';')
                if sep >= 0:
                    line = line[:sep]
                try:
                    chunk_size = int(line, 16)
                except ValueError:
                    self.close(True)
                if chunk_size < 0:
                    self.close(True)
                self.chunk_left = chunk_size

                if chunk_size == 0:
                    # Body terminator received; trailers follow until blank.
                    # An EOF here still counts as clean body completion.
                    while True:
                        line = self._sock.readline()
                        if not line or line == _CRLF or line == b"\n":
                            self.chunk_left = None
                            self.close()
                            break
                    break

            if arg_is_memoryview:
                space = len(res) - total
                to_read = self.chunk_left
                if to_read > space:
                    to_read = space
                # Common-case optimization: pass the whole buffer + nbytes cap
                # to skip allocating a memoryview slice.
                if total == 0:
                    nread = self._sock.readinto(res, to_read)
                else:
                    nread = self._sock.readinto(res[total:total+to_read])
                if not nread:
                    self.close(True)
                self._bytes_read += nread
                total += nread
                self.chunk_left -= nread
            else:
                if arg is None:
                    to_read = self.chunk_left
                else:
                    remaining_req = arg - total
                    to_read = self.chunk_left
                    if to_read > remaining_req:
                        to_read = remaining_req
                chunk = self._sock.read(to_read)
                if not chunk:
                    self.close(True)
                self._bytes_read += len(chunk)
                total += len(chunk)
                self.chunk_left -= len(chunk)
                parts.append(chunk)

            if self.chunk_left == 0:
                line = self._sock.readline()
                if not line:
                    self.close(True)
                if line != _CRLF and line != b"\n":
                    self.close(True)
                self.chunk_left = None

            if arg_is_memoryview:
                if total >= len(res):
                    break
            elif arg is not None:
                if total >= arg:
                    break
            # arg is None -> drain until the terminator chunk.

        if arg_is_memoryview:
            return total
        else:
            return parts

    def _read_raw(self, arg=None):
        # Blocking socket assumed. arg modes:
        #   memoryview -> fill it, return int bytes-written
        #   None       -> read all (bounded by CL if set), return bytes
        #   int        -> read up to that many (bounded by CL), return bytes
        # Negative ints are coerced to None. Zero is filtered upstream.
        arg_is_memoryview = isinstance(arg, memoryview)
        if arg_is_memoryview:
            res = arg
        elif arg is not None:
            arg = int(arg)
            if arg < 0:
                arg = None

        if self.isclosed():
            if arg_is_memoryview:
                return 0
            else:
                return None

        # No CL and unbounded request -> read-until-EOF framing.
        if arg is None and self.length is None:
            chunk = self._sock.read()
            self._bytes_read += len(chunk)
            self.close()
            return chunk

        if self.length is None:
            if arg_is_memoryview:
                to_read = len(res)
            else:
                to_read = arg
        else:
            remaining = self.length - self._bytes_read
            if arg is None:
                to_read = remaining
            elif arg_is_memoryview:
                to_read = min(remaining, len(res))
            else:
                to_read = min(remaining, arg)

        if to_read < 0:
            self.close(True)

        chunk = None
        total = 0

        # to_read can legitimately be 0 here (HEAD, 204, 304, or CL already
        # satisfied). Skip the socket call but still run the close block below.
        if to_read > 0:
            if arg_is_memoryview:
                nread = self._sock.readinto(res, to_read)
                if not nread:
                    if self.length is not None and self._bytes_read < self.length:
                        self.close(True)
                    self.close()
                    return 0
                self._bytes_read += nread
                total = nread
            else:
                chunk = self._sock.read(to_read)
                if not chunk:
                    if self.length is not None and self._bytes_read < self.length:
                        self.close(True)
                    self.close()
                    return None
                self._bytes_read += len(chunk)

        if self.length is not None:
            if self._bytes_read == self.length:
                self.close()
            elif self._bytes_read > self.length:
                # Defensive: to_read math should prevent this.
                self.close(True)
            elif arg is None:
                self.close(True)

        if arg_is_memoryview:
            return total
        else:
            return chunk

    def getheaders(self):
        if self.headers is None:
            raise ResponseNotReady()
        return [(k.decode(_DECODE_HEAD), v.decode(_DECODE_HEAD)) for k, v in self.headers]

    def getheader(self, key, default=None):
        val = self.getheader_bytes(key)
        if val is not None:
            return val.decode(_DECODE_HEAD)
        return default

    def getheader_bytes(self, key, default=None):
        if self.headers is None:
            raise ResponseNotReady()
        key = _normalize_key(key)
        matches = [v for k, v in self.headers if k == key]
        if not matches:
            return default
        if len(matches) == 1:
            return matches[0]
        return b", ".join(matches)

    def _getheader_bytes(self, key, default=None):
        # First-match fast path; assumes key already normalized.
        for k, v in self.headers:
            if k == key:
                return v
        return default

    def getcookies_bytes(self):
        if self.headers is None:
            raise ResponseNotReady()
        return [v for k, v in self.headers if k == b"set-cookie"]

    # Yields fresh bytes chunks of up to chunk_size each.
    def iter_content(self, chunk_size=1024):
        chunk_size = int(chunk_size)
        if chunk_size <= 0:
            raise ValueError("chunk_size must be > 0")
        if self.length is not None:
            remaining = self.length - self._bytes_read
            if remaining <= 0:
                return
            if chunk_size > remaining:
                chunk_size = remaining
        buf = bytearray(chunk_size)
        bmv = memoryview(buf)
        while True:
            n = self._readinto(bmv)
            if n <= 0:
                break
            if n == chunk_size:
                yield bytes(buf)
            else:
                yield bytes(bmv[:n])

    # Fills the caller's buffer in place, yields bytes-written counts.
    def iter_content_into(self, bmv):
        if not isinstance(bmv, memoryview):
            bmv = memoryview(bmv)
        while True:
            n = self._readinto(bmv)
            if n <= 0:
                return
            yield n

class HTTPConnection:
    _buffer_size = 1024
    default_port = HTTP_PORT
    auto_open = True
    debuglevel = 0

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        return False

    def __init__(self, host, port=None, timeout=None, source_address=None, blocksize=1024):
        self.host, self.port = self._parse_host_port(host, port)
        self.timeout = timeout
        self.blocksize = blocksize
        self.sock = None
        self.__response = None
        self._auto_open = False
        if self._buffer_size:
            self._buffmv = memoryview(bytearray(self._buffer_size))
        else:
            self._buffmv = None
        self._filled = 0
        self._method = None
        self._url = None

    def set_debuglevel(self, level):
        self.debuglevel = level

    def connect(self):
        self.sock = create_connection((self.host, self.port), self.timeout)

    def close(self):
        self._filled = 0
        sock = self.sock
        self.sock = None
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        response = self.__response
        self.__response = None
        if response is not None:
            response.close()

    def _parse_host_port(self, host, port):
        parsed_port = None
        if host.startswith('['):
            close = host.rfind(']')
            if close == -1:
                raise ValueError("invalid host")
            host, rest = host[1:close], host[close+1:]
            if rest.startswith(':'):
                if len(rest) > 1:
                    parsed_port = rest[1:]
            elif rest:
                raise ValueError("invalid host")
        elif host.count(':') == 1:
            host, parsed_port = host.rsplit(':', 1)
        if port is None:
            port = parsed_port
        if not host:
            raise ValueError("invalid host")
        if not port:
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
            # Materialize once: a generator would be exhausted by the scan
            # below and have nothing left for the send loop.
            if hasattr(headers, "items") and callable(headers.items):
                headers = headers.items()
            if not isinstance(headers, (list, tuple)):
                headers = list(headers)
            for key, val in headers:
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
            body = body.encode(_ENCODE_BODY)

        if encode_chunked is None:
            if body is None:
                encode_chunked = False
            elif isinstance(body, (bytes, bytearray, memoryview)):
                encode_chunked = False
                if not have_content_length:
                    self.putheader(b"Content-Length", str(len(body)))
            else:
                encode_chunked = not have_content_length
        if encode_chunked and not have_transfer_encoding:
            self.putheader(b"Transfer-Encoding", b"chunked")

        if headers is not None:
            for key, val in headers:
                self.putheader(key, val)

        self.endheaders(body, encode_chunked=encode_chunked)

    def putrequest(self, method, url, skip_host=False, skip_accept_encoding=False):
        if self.__response is not None and not self.__response.isclosed():
            raise CannotSendRequest()
        self.__response = None

        self._auto_open = self.auto_open
        self._filled = 0

        self._method = _encode_and_validate(method, "ascii", 1)
        if self._method != b"GET":
            self._method = self._method.upper()

        if url is not None:
            self._url = _encode_and_validate(url, _ENCODE_HEAD, 1) or b"/"
        else:
            self._url = b"/"

        self._putheaderparts(False, self._method, b" ", self._url, b" HTTP/1.1\r\n")

        if not skip_host:
            host_bytes = self.host.encode(_ENCODE_HEAD)
            if b':' in host_bytes and not host_bytes.startswith(b'['):
                host_bytes = b"[" + host_bytes + b"]"
            if self.port == self.default_port:
                self.putheader(b"Host", host_bytes)
            else:
                self.putheader(b"Host", b"%s:%d" % (host_bytes, self.port))
        if not skip_accept_encoding:
            self._putheaderparts(False, b"Accept-Encoding: identity\r\n")

    def putheader(self, header, value):
        if self.__response is not None:
            raise CannotSendHeader()
        if isinstance(header, str):
            header = header.encode(_ENCODE_HEAD)
        self._putheaderparts(False, header, b": ", _encode_and_validate(value, _ENCODE_HEAD, 0), _CRLF)

    def _putheaderparts(self, last, *parts):
        # Coalesces small writes into a single sendall. last=True flushes.
        if self._buffmv is None:
            self._send_raw(_BLANK.join(parts))
        else:
            for part in parts:
                len_part = len(part)
                if len_part >= self._buffer_size:
                    if self._filled:
                        self._send_raw(self._buffmv[:self._filled])
                        self._filled = 0
                    self._send_raw(part)
                elif self._filled + len_part <= self._buffer_size:
                    self._buffmv[self._filled:self._filled+len_part] = part
                    self._filled += len_part
                else:
                    self._send_raw(self._buffmv[:self._filled])
                    self._buffmv[:len_part] = part
                    self._filled = len_part

        if last and self._filled:
            self._send_raw(self._buffmv[:self._filled])
            self._filled = 0

    def endheaders(self, message_body=None, *, encode_chunked=False):
        if self.__response is not None:
            raise CannotSendHeader()
        self._putheaderparts(True, _CRLF)
        self._auto_open = False
        if message_body is not None or encode_chunked:
            self.send(message_body, encode_chunked=encode_chunked)

    def _send_raw(self, data):
        # On the first send of a request, transparently (re)connect if a
        # kept-alive socket has died. Subsequent sends require an open socket.
        if not data:
            return

        if self._auto_open:
            try:
                if self.sock is not None:
                    self.sock.sendall(data)
                    self._auto_open = False
                    return
            except OSError:
                try: self.sock.close()
                except Exception: pass
                self.sock = None
            try:
                self.connect()
            except OSError:
                raise NotConnected()
            self.sock.sendall(data)
            self._auto_open = False
            return

        if self.sock is None:
            raise NotConnected()
        self.sock.sendall(data)
        self._auto_open = False

    def _send_chunk(self, data):
        # data=None emits the terminating chunk.
        if data is None:
            self._send_raw(b"0\r\n\r\n")
            return
        if data:
            self._send_raw(b"%X\r\n" % (len(data),))
            self._send_raw(data)
            self._send_raw(_CRLF)

    # encode_chunked and final_chunk are extensions beyond CPython.
    def send(self, data, *, encode_chunked=False, final_chunk=True):
        send = self._send_chunk if encode_chunked else self._send_raw

        if isinstance(data, str):
            data = data.encode(_ENCODE_BODY)

        if data is None:
            if self.debuglevel > 0:
                print("send: None")
            pass

        elif isinstance(data, (bytes, bytearray, memoryview)):
            if self.debuglevel > 0:
                print("send:", type(data).__name__, len(data))
            if data:
                send(data)

        else:
            if self.debuglevel > 0:
                print("send:", type(data).__name__)
            for d in data:
                if isinstance(d, str):
                    d = d.encode(_ENCODE_BODY)
                if d is not None:
                    send(d)

        if encode_chunked and final_chunk:
            if self.debuglevel > 0:
                print("send: terminator")
            send(None)

    def getresponse(self, **kwargs):
        if self.__response is not None and not self.__response.isclosed():
            raise ResponseNotReady()
        self.__response = None

        response = HTTPResponse(self.sock, self.debuglevel, self._method, self._url)
        try:
            response.begin(**kwargs)
            if response.will_close:
                # The response owns the socket now and will close it.
                self.sock = None
                self.__response = None
            else:
                self.__response = response
            return response
        except Exception as e:
            # The response owns the socket on this path -- close through it so
            # we don't double-close. Don't use close(True): it would raise
            # IncompleteRead and mask the original BadStatusLine/etc.
            # will_close is True from __init__ and only relaxes after a
            # successful header parse, so begin()-raises always mean we close.
            self.sock = None
            self.__response = None
            if not isinstance(e, OSError):
                response._tainted = True
            response.close()
            raise

    def detach(self):
        # Hand the socket back to the caller and reset our state.
        if self.__response is not None:
            sock = self.__response._sock
            self.__response._sock = None
            self.__response = None
        else:
            sock = self.sock
        self.sock = None
        return sock

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
                # NB: certificate verification is OFF by default for embedded
                # use. Pass a configured context to enable it.
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.verify_mode = ssl.CERT_NONE
            self._context = context

        def connect(self):
            super().connect()
            raw = self.sock
            try:
                # SNI is omitted for IP literals (per RFC 6066).
                use_sni = not (':' in self.host or all(c.isdigit() or c == '.' for c in self.host))
                self.sock = self._context.wrap_socket(raw, server_hostname=self.host if use_sni else None)
            except Exception:
                self.sock = None
                try:
                    raw.close()
                except OSError:
                    pass
                raise
