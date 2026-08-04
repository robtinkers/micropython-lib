# urllib/parse.py
#
# urllib.parse for Micropython, optimised for memory footprint and churn.

import micropython

_BYTE_SEQUENCES = (str, bytes, bytearray, memoryview)

_USES_RELATIVE = frozenset([
    "", "file", "ftp", "http", "https", "shttp", "rtsp", "rtsps", "rtspu",
    "sftp", "ws", "wss",
])

_USES_NETLOC = _USES_RELATIVE

_WHATWG_C0_AND_SPACE = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"

_HEX_DIGITS = b"0123456789ABCDEF"

# Standard safeblob for ASCII 32-127, stored as four little-endian words.
# The flags word is [mode, 0x66, 0x99, 0x00], so its middle bytes also act as
# a byte-order marker. The remaining words cover 32-63, 64-95, and 96-127.
_COMPILED_EMPTY = (
    b"\x00\x66\x99\x00"
    b"\x00\x60\xff\x03"  # 0-9, -, .
    b"\xfe\xff\xff\x87"  # A-Z, _
    b"\xfe\xff\xff\x47"  # a-z, ~
)
_COMPILED_SLASH = (
    b"\x00\x66\x99\x00"
    b"\x00\xe0\xff\x03"  # slash
    b"\xfe\xff\xff\x87"
    b"\xfe\xff\xff\x47"
)
_COMPILED_PLUS = (
    b"\x01\x66\x99\x00"  # plus mode
    b"\x00\x60\xff\x03"
    b"\xfe\xff\xff\x87"
    b"\xfe\xff\xff\x47"
)

class _compiled_blob(bytearray):
    def __init__(self):
        super().__init__(_COMPILED_EMPTY)

def compile_safe(safe, flags=0):
    """Compile safe characters into a 16-byte bytearray."""
    if flags not in (0, 1):
        raise ValueError("flags must be 0 (quote) or 1 (quote_plus)")
    safeblob = _compiled_blob()
    safeblob[0] = flags
    for c in safe:
        if isinstance(c, str):
            c = ord(c)
        if 32 <= c <= 127:
            safeblob[c >> 3] |= 1 << (c & 7)
    return safeblob

@micropython.viper
def _quote_helper(src: ptr8, srclen: int, safeblob_obj: object, out: ptr8) -> int:
    safeblob = ptr32(safeblob_obj)
    write = int(out) != 0
    modified = 0
    outlen = 0
    b = 0

    # Unpack safeblob into local variables for speed
    flags = safeblob[0]
    if (flags & 0x00FFFF00) != 0x00996600:
        return -1
    flags &= 0xFF
    safe1 = safeblob[1] # 32-63
    safe2 = safeblob[2] # 64-95
    safe3 = safeblob[3] # 96-127

    hex_digits = ptr8(_HEX_DIGITS)

    i = 0
    while i < srclen:
        b = src[i]
        i += 1

        if b == 32 and flags == 1: # space and quote_plus
            modified = 1
            if write:
                out[outlen] = 43 # '+'
            outlen += 1
            continue

        if b < 32:
            is_safe = 0
        elif b < 64:
            is_safe = (safe1 >> (b & 31)) & 1
        elif b < 96:
            is_safe = (safe2 >> (b & 31)) & 1
        elif b < 128:
            is_safe = (safe3 >> (b & 31)) & 1
        else:
            is_safe = 0

        if is_safe:
            if write:
                out[outlen] = b
            outlen += 1
        else:
            modified = 1
            if write:
                out[outlen] = 37 # '%'
                out[outlen + 1] = hex_digits[b >> 4]
                out[outlen + 2] = hex_digits[b & 0xF]
            outlen += 3

    return outlen if modified else 0

def _quote(s, safe, flags):
    if not isinstance(s, _BYTE_SEQUENCES):
        raise TypeError("quote input must be str or bytes-like")

    if isinstance(safe, _compiled_blob):
        if len(safe) != 16 or safe[0] != flags:
            raise TypeError("pre-compiled safe is incompatible with current method")
    elif not safe:                                 # "" or b""
        safe = _COMPILED_PLUS if flags else _COMPILED_EMPTY
    elif not flags and len(safe) == 1 and safe[0] in (47, "/"):  # "/" or b"/"
        safe = _COMPILED_SLASH
    else:
        safe = compile_safe(safe, flags)

    if isinstance(s, str):
        # on micropython, memoryview(str) gives you direct access to the underlying bytes
        src = memoryview(s)
    else:
        src = s
    srclen = len(src)
    outlen = _quote_helper(src, srclen, safe, 0)
    if outlen < 0:
        raise NotImplementedError("compiled safe blobs require little-endian byte order")
    if srclen == 0:
        return ""
    if outlen == 0:
        if isinstance(s, str):
            return s
        if isinstance(s, memoryview):
            s = bytes(s)
        return s.decode()

    out = bytearray(outlen)
    _quote_helper(src, srclen, safe, out)
    return out.decode()

def quote(s, safe="/"):
    return _quote(s, safe, 0)

def quote_plus(s, safe=""):
    return _quote(s, safe, 1)

def quote_from_bytes(bs, safe="/"):
    if not isinstance(bs, (bytes, bytearray)):
        raise TypeError("quote_from_bytes() expected bytes")
    return _quote(bs, safe, 0)

@micropython.viper
def _unquote_helper(src: ptr8, start: int, end: int, out: ptr8) -> int:
    if end < 0:
        end = -end
        plusmode = 1
    else:
        plusmode = 0
    write = int(out) != 0
    modified = 0
    outlen = 0
    n1 = n2 = c = b = 0

    i = start
    while i < end:
        b = src[i]
        i += 1

        if b == 37 and i + 1 < end: # '%'
            c = src[i]
            if 48 <= c and c <= 57: # 0-9
                n1 = c - 48
            else:
                c |= 32 # A-F -> a-f
                if 97 <= c and c <= 102: # a-f
                    n1 = c - 87
                else:
                    n1 = 255

            if n1 != 255:
                c = src[i + 1]
                if 48 <= c and c <= 57:
                    n2 = c - 48
                else:
                    c |= 32
                    if 97 <= c and c <= 102:
                        n2 = c - 87
                    else:
                        n2 = 255

                if n2 != 255:
                    modified = 1
                    b = (n1 << 4) | n2
                    i += 2

        elif b == 43 and plusmode: # '+'
            modified = 1
            b = 32 # space

        if write:
            out[outlen] = b
        outlen += 1

    return outlen if modified else -outlen

def _unquote(s, start, end, plusmode: bool):
    # Returns a bytes-like object that supports .decode(): bytes or bytearray.
    # Callers that need real bytes (unquote_to_bytes) must materialise it.
    if isinstance(s, str):
        # on micropython, memoryview(str) gives you direct access to the underlying bytes
        # but you're going to have a hard time unless (start == 0 and end is None)
        assert(start == 0 and end is None)
        src = memoryview(s)
    else:
        src = s
    srclen = len(src)
    if end is None:
        end = srclen
    assert(0 <= start <= end <= srclen)
    if start == end:
        return b""

    endx = -end if plusmode else end
    outlen = _unquote_helper(src, start, endx, 0)
    if outlen >= 0:
        out = bytearray(outlen)
        _unquote_helper(src, start, endx, out)
        return out

    if start != 0 or end != srclen:
        out = src[start:end]
    else:
        out = src

    if isinstance(out, memoryview):
        out = bytes(out)
    return out

def unquote(s):
    return _unquote(s, 0, None, False).decode()

def unquote_plus(s):
    return _unquote(s, 0, None, True).decode()

def unquote_to_bytes(s) -> bytes:
    out = _unquote(s, 0, None, False)
    if not isinstance(out, bytes):
        out = bytes(out)
    return out

def _urlencode_generator(query, doseq=False, safe="", quote_via=quote_plus):
    if hasattr(query, "items"):
        query = query.items()
    for key, val in query:
        if not isinstance(key, _BYTE_SEQUENCES):
            key = str(key)
        key = quote_via(key, safe)

        if not isinstance(val, _BYTE_SEQUENCES):
            if doseq:
                try:
                    len(val)
                except TypeError:
                    pass
                else:
                    for v in val:
                        if not isinstance(v, _BYTE_SEQUENCES):
                            v = str(v)
                        yield key + "=" + quote_via(v, safe)
                    continue
            val = str(val)
        yield key + "=" + quote_via(val, safe)

def urlencode(query, *args, **kwargs) -> str:
    return "&".join(_urlencode_generator(query, *args, **kwargs))

@micropython.viper
def _mv_find(mv: ptr8, b: int, start: int, end: int) -> int:
    i = start
    while i < end:
        if mv[i] == b:
            return i
        i += 1
    return -1

def _parse_generator(s, keep_blank_values=False, strict_parsing=False,
                     errors="ignore", separator='&', max_num_fields=None,
                     _decode=True):
    if isinstance(s, str):
        # on micropython, memoryview(str) gives you direct access to the underlying bytes
        src = memoryview(s)
    else:
        src = s
    srclen = len(src)
    if srclen == 0:
        return

    sep = ord(separator)  # works if separator is string-like length 1; otherwise error
    i = 0
    num_fields = 0

    while i <= srclen:
        if max_num_fields is not None:
            num_fields += 1
            if num_fields > max_num_fields:
                raise ValueError("Max number of fields exceeded")
        j = _mv_find(src, sep, i, srclen)
        if j < 0:
            j = srclen
        if i == j:
            if strict_parsing:
                raise ValueError("bad query field")
            i = j + 1
            continue

        eq = _mv_find(src, 61, i, j) # '='

        try:
            if eq < 0:
                # key (no '=')
                if strict_parsing:
                    raise ValueError("bad query field")
                if keep_blank_values:
                    key = _unquote(src, i, j, True)
                    val = b""
                    if _decode:
                        key = key.decode()
                        val = ""
                    elif not isinstance(key, bytes):
                        key = bytes(key)
                    yield key, val
            else:
                # key=value
                if keep_blank_values or (eq + 1 < j):
                    key = _unquote(src, i, eq, True)
                    val = _unquote(src, eq + 1, j, True)
                    if _decode:
                        key = key.decode()
                        val = val.decode()
                    else:
                        if not isinstance(key, bytes):
                            key = bytes(key)
                        if not isinstance(val, bytes):
                            val = bytes(val)
                    yield key, val
        except UnicodeError:
            if errors != "ignore":
                raise

        i = j + 1

def parse_qs(qs, *args, **kwargs) -> dict:
    _decode = isinstance(qs, str)
    out = {}
    for key, val in _parse_generator(qs, *args, **kwargs, _decode=_decode):
        if key in out:
            out[key].append(val)
        else:
            out[key] = [val]
    return out

def parse_qsl(qs, *args, **kwargs) -> list:
    _decode = isinstance(qs, str)
    return list(_parse_generator(qs, *args, **kwargs, _decode=_decode))

def urldecode(qs, *args, **kwargs) -> dict:
    _decode = isinstance(qs, str)
    out = {}
    for key, val in _parse_generator(qs, *args, **kwargs, _decode=_decode):
        out[key] = val
    return out

# Extension
def locsplit_as_tuple(netloc: str) -> tuple:
    if (sep := netloc.rfind('@')) >= 0:
        userpass, hostport = netloc[:sep], netloc[sep+1:]
        if (sep := userpass.find(':')) >= 0:
            username, password = userpass[:sep], userpass[sep+1:]
        else:
            username, password = userpass, None
    else:
        hostport = netloc
        username, password = None, None

    if hostport and hostport.startswith('['): # Handle IPv6 (simple check)
        if (sep := hostport.find(']')) >= 0:
            host, port = hostport[1:sep], hostport[sep+1:]
        else: # *shrug*
            host, port = hostport, ""
    else:
        if (sep := hostport.rfind(':')) >= 0:
            host, port = hostport[:sep], hostport[sep:]
        else:
            host, port = hostport, ""

    if host:
        # Preserve zone ID case for IPv6 scoped addresses
        if (sep := host.find('%')) >= 0:
            host = host[:sep].lower() + host[sep:]
        else:
            host = host.lower()
    else:
        host = None

    if port == "":
        port = None
    elif len(port) > 1 and port.startswith(':'):
        p = port[1:]
        if p.isdigit(): # reject '+80', ' 80', '80 ' etc.
            p = int(p, 10)
            if 0 <= p <= 65535:
                port = p

    return (username, password, host, port)

# Extension
def locsplit(netloc: str) -> dict:
    return dict(zip(('username', 'password', 'hostname', 'port'), locsplit_as_tuple(netloc)))

# Derived from CPython (all bugs are mine)
def urlsplit_as_tuple(url: str, scheme, allow_fragments: bool) -> tuple:
    # Only lstrip url, as some applications rely on preserving trailing space.
    # (https://url.spec.whatwg.org/#concept-basic-url-parser would strip both)
    url = url.lstrip(_WHATWG_C0_AND_SPACE)

    if scheme:
        scheme = scheme.strip(_WHATWG_C0_AND_SPACE)

    netloc = query = fragment = None
    if (colon := url.find(':')) > 0 and url[0].isalpha():
        if (slash := url.find('/')) < 0 or colon < slash:
            scheme, url = url[:colon].lower(), url[colon+1:]
    if url.startswith("//"):
        delim = len(url)
        for c in "/?#":
            if 0 <= (x := url.find(c, 2)) < delim:
                delim = x
        netloc, url = url[2:delim], url[delim:]

    if allow_fragments and (i := url.find('#')) >= 0:
        url, fragment = url[:i], url[i+1:]

    if (i := url.find('?')) >= 0:
        url, query = url[:i], url[i+1:]

    return (scheme, netloc, url, query, fragment)

class SplitResult(tuple):

    def __init__(self, scheme, netloc, path, query, fragment):
        super().__init__((scheme or "", netloc or "", path, query or "", fragment or ""))
        self._locsplit_ = None

    @property
    def _locsplit(self):
        if self._locsplit_ is None:
            self._locsplit_ = locsplit_as_tuple(self[1])
        return self._locsplit_

    @property
    def scheme(self): return self[0]

    @property
    def netloc(self): return self[1]

    @property
    def path(self): return self[2]

    @property
    def query(self): return self[3]

    @property
    def fragment(self): return self[4]

    @property
    def username(self): return self._locsplit[0]

    @property
    def password(self): return self._locsplit[1]

    @property
    def hostname(self): return self._locsplit[2]

    @property
    def port(self):
        port = self._locsplit[3]
        if port is None or isinstance(port, int):
            return port
        if port == ":":
            return None
        raise ValueError("bad port number")

    def geturl(self):
        return urlunsplit(self)

def urlsplit(url: str, scheme=None, allow_fragments=True) -> SplitResult:
    return SplitResult(*urlsplit_as_tuple(url, scheme, allow_fragments))

def _urlunsplit(scheme, netloc, path, query, fragment) -> str:
    parts = []

    if scheme is not None:
        parts.append(scheme)
        parts.append(":")

    if netloc is not None:
        parts.append("//")
        parts.append(netloc)
        if path and not path.startswith("/"):
            parts.append("/")
    else:
        if path and path.startswith("//"):
            parts.append("//")
    if path:
        parts.append(path)

    if query is not None:
        parts.append("?")
        parts.append(query)

    if fragment is not None:
        parts.append("#")
        parts.append(fragment)

    return "".join(parts)

def urlunsplit(components: tuple) -> str:
    scheme, netloc, path, query, fragment = components
    if not netloc:
        if scheme and scheme in _USES_NETLOC and (not path or path.startswith('/')):
            netloc = ""
        else:
            netloc = None
    return _urlunsplit(scheme or None, netloc, path or "", query or None, fragment or None)

# Derived from CPython (all bugs are mine)
def urljoin(base: str, url: str, allow_fragments: bool=True) -> str:
    if not base:
        return url
    if not url:
        return base

    bscheme, bnetloc, bpath, bquery, bfragment = urlsplit_as_tuple(base, None, allow_fragments)
    scheme, netloc, path, query, fragment = urlsplit_as_tuple(url, None, allow_fragments)

    if scheme is None:
        scheme = bscheme
    if scheme != bscheme or (scheme and scheme not in _USES_RELATIVE):
        return url
    if not scheme or scheme in _USES_NETLOC:
        if netloc:
            return _urlunsplit(scheme, netloc, path, query, fragment)
        netloc = bnetloc

    if not path:
        path = bpath
        if query is None:
            query = bquery
            if fragment is None:
                fragment = bfragment
        return _urlunsplit(scheme, netloc, path, query, fragment)

    base_parts = bpath.split('/')
    if base_parts[-1] != "":
        # the last item is not a directory, so will not be taken into account
        # in resolving the relative path
        del base_parts[-1]

    # for rfc3986, ignore all base path should the first character be root.
    if path.startswith('/'): # `not path` was already checked earlier
        segments = path.split('/')
    else:
        segments = base_parts + path.split('/')
        # Remove empty segments in the middle (keep first and last as-is)
        w = 1
        for r in range(1, len(segments) - 1):
            seg = segments[r]
            if seg:
                segments[w] = seg
                w += 1
        # delete the now-unused tail (but preserve the last element)
        del segments[w:len(segments) - 1]

    resolved_path = []
    for seg in segments:
        if seg == "..":
            if resolved_path:
                resolved_path.pop()
        elif seg != ".":
            resolved_path.append(seg)

    if segments[-1] in (".", ".."):
        # do some post-processing here. if the last segment was a relative dir,
        # then we need to append the trailing '/'
        resolved_path.append("")

    return _urlunsplit(scheme, netloc, "/".join(resolved_path) or "/", query, fragment)
