# urllib/parse.py
#
# Serious parsing for tiny devices.

import micropython

_USES_RELATIVE = (
    "http", "https", "ws", "wss", "ftp", "file",
    "sftp", "rtsp", "rtsps", "rtspu", "shttp",
)

_USES_NETLOC = _USES_RELATIVE

_HEX_DIGITS = b"0123456789ABCDEF"

_COMPILED_EMPTY = (
    b"\x00\x00\x00\x69"
    b"\x00\x60\xff\x03"  # 0-9 - .
    b"\xfe\xff\xff\x87"  # A-Z _
    b"\xfe\xff\xff\x47"  # a-z ~
)
_COMPILED_SLASH = (
    b"\x00\x00\x00\x69"
    b"\x00\xe0\xff\x03"  # /
    b"\xfe\xff\xff\x87"
    b"\xfe\xff\xff\x47"
)
_COMPILED_PLUS = (
    b"\x01\x00\x00\x69"  # plus mode
    b"\x00\x60\xff\x03"
    b"\xfe\xff\xff\x87"
    b"\xfe\xff\xff\x47"
)

class _compiled_safe(bytearray):
    def __init__(self):
        super().__init__(_COMPILED_EMPTY)

def compile_safe(safe, flags=0):
    if flags not in (0, 1):
        raise ValueError("flags must be 0 (quote) or 1 (quote_plus)")
    compiled = _compiled_safe()
    compiled[0] |= flags
    for c in safe:
        if isinstance(c, str):
            c = ord(c)
        if 32 <= c <= 127:
            compiled[c >> 3] |= 1 << (c & 7)
    return compiled

@micropython.viper
def _quote_helper(src: ptr8, srclen: int, safe_obj: object, res: ptr8) -> int:
    safe_ptr = ptr8(safe_obj)
    if len(safe_obj) != 16 or safe_ptr[3] != 0x69:
        raise ValueError("invalid compiled safe")
    plusmode = safe_ptr[0] & 1
    mutable = int(res) != 0

    hex_digits = ptr8(_HEX_DIGITS)
    modified = 0
    reslen = 0
    i = 0

    while i < srclen:
        b = src[i]
        i += 1

        if b == 32 and plusmode:
            modified = 1
            if mutable:
                res[reslen] = 43
            reslen += 1
            continue

        if 32 <= b and b < 128:
            is_safe = (safe_ptr[b >> 3] >> (b & 7)) & 1
        else:
            is_safe = 0

        if is_safe:
            if mutable:
                res[reslen] = b
            reslen += 1
        else:
            modified = 1
            if mutable:
                res[reslen] = 37
                res[reslen + 1] = hex_digits[b >> 4]
                res[reslen + 2] = hex_digits[b & 15]
            reslen += 3

    return reslen if modified else -1

def _quote(src, safe, flags):
    srclen = len(src)
    compiled = isinstance(safe, _compiled_safe)

    if compiled:
        if len(safe) != 16 or safe[0] != flags:
            raise TypeError("incompatible safe")

    if srclen == 0:
        return None

    if compiled:
        pass
    elif not safe:
        safe = _COMPILED_PLUS if flags else _COMPILED_EMPTY
    elif not flags and len(safe) == 1 and safe[0] in (47, "/"):
        safe = _COMPILED_SLASH
    else:
        safe = compile_safe(safe, flags)

    reslen = _quote_helper(src, srclen, safe, 0)
    if reslen < 0:
        return None

    res = bytearray(reslen)
    _quote_helper(src, srclen, safe, res)
    return res

def quote(s, safe="/"):
    if isinstance(s, str):
        res = _quote(memoryview(s), safe, 0)
        if res is None:
            return s
    elif isinstance(s, (bytes, bytearray)):
        res = _quote(s, safe, 0)
        if res is None:
            res = s
    else:
        raise TypeError()
    return res.decode()

def quote_plus(s, safe=""):
    if isinstance(s, str):
        res = _quote(memoryview(s), safe, 1)
        if res is None:
            return s
    elif isinstance(s, (bytes, bytearray)):
        res = _quote(s, safe, 1)
        if res is None:
            res = s
    else:
        raise TypeError()
    return res.decode()

def quote_from_bytes(bs, safe="/"):
    if not isinstance(bs, (bytes, bytearray)):
        raise TypeError("bytes required")
    return quote(bs, safe)

# Extension
def quote_to_bytes(s, safe="/"):
    if isinstance(s, str):
        res = _quote(memoryview(s), safe, 0)
        if res is None:
            return s.encode()
    elif isinstance(s, bytes):
        res = _quote(s, safe, 0)
        if res is None:
            return s
    elif isinstance(s, bytearray):
        res = _quote(s, safe, 0)
        if res is None:
            return bytes(s)
    else:
        raise TypeError()
    return res

# Extension
def quote_plus_to_bytes(s, safe=""):
    if isinstance(s, str):
        res = _quote(memoryview(s), safe, 1)
        if res is None:
            return s.encode()
    elif isinstance(s, bytes):
        res = _quote(s, safe, 1)
        if res is None:
            return s
    elif isinstance(s, bytearray):
        res = _quote(s, safe, 1)
        if res is None:
            return bytes(s)
    else:
        raise TypeError()
    return res

@micropython.viper
def _unquote_helper(src: ptr8, start: int, end: int, res: ptr8) -> int:
    if end < 0:
        end = -end
        plusmode = 1
    else:
        plusmode = 0
    mutable = int(res) != 0

    modified = 0
    reslen = 0
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

        if mutable:
            res[reslen] = b
        reslen += 1

    return reslen if modified else -reslen

def _unquote(src, start, end, plusmode):
    srclen = len(src)
    if end is None:
        end = srclen
    assert(0 <= start <= end <= srclen)
    if start == end:
        return b""

    endx = -end if plusmode else end
    reslen = _unquote_helper(src, start, endx, 0)
    if reslen >= 0:
        res = bytearray(reslen)
        _unquote_helper(src, start, endx, res)
        return res

    if start != 0 or end != srclen:
        res = src[start:end]
    else:
        res = src
    if isinstance(res, memoryview):
        res = bytes(res)
    return res

def unquote(s):
    if isinstance(s, str):
        if "%" not in s:
            return s
        s = memoryview(s)
    return _unquote(s, 0, None, False).decode()

def unquote_plus(s):
    if isinstance(s, str):
        if "%" not in s and "+" not in s:
            return s
        s = memoryview(s)
    return _unquote(s, 0, None, True).decode()

def unquote_to_bytes(s):
    if isinstance(s, str):
        s = memoryview(s)
    res = _unquote(s, 0, None, False)
    if res is s and not isinstance(res, bytes):
        res = bytes(res)
    return res

# Extension
def unquote_plus_to_bytes(s):
    if isinstance(s, str):
        s = memoryview(s)
    res = _unquote(s, 0, None, True)
    if res is s and not isinstance(res, bytes):
        res = bytes(res)
    return res

# Extension
def locsplit_to_tuple(netloc, *, missing_as_none=False):
    if netloc is None:
        if missing_as_none:
            return (None, None, None, None)
        raise TypeError("netloc must be str or bytes")

    ss = isinstance(netloc, str)
    _check_authority(netloc, ss)
    missing = None if missing_as_none else "" if ss else b""

    if (sep := netloc.rfind('@' if ss else b'@')) >= 0:
        userpass, hostport = netloc[:sep], netloc[sep+1:]
        if (sep := userpass.find(':' if ss else b':')) >= 0:
            username, password = userpass[:sep], userpass[sep+1:]
        else:
            username, password = userpass, missing
    else:
        hostport = netloc
        username, password = missing, missing

    if (sep := hostport.find('[' if ss else b'[')) >= 0:
        if (0 == sep < (port := hostport.find(']' if ss else b']', sep))):
            host, port = hostport[sep+1:port], hostport[port+1:]
        else:
            raise ValueError("bad IPv6 address")
    elif (sep := hostport.find(':' if ss else b':')) >= 0:
        host, port = hostport[:sep], hostport[sep:]
    else:
        host, port = hostport, missing

    if host:
        # Preserve zone ID case for IPv6 scoped addresses
        if (sep := host.find('%' if ss else b'%')) >= 0:
            host = host[:sep].lower() + host[sep:]
        else:
            host = host.lower()
    else:
        host = None

    if not port:
        port = missing
    elif len(port) > 1 and port.startswith(':' if ss else b':'):
        p = port[1:]
        if p.isdigit(): # reject '+80', ' 80', '80 ' etc.
            p = int(p, 10)
            if 0 <= p <= 65535:
                port = p

    return (username, password, host, port)

# Extension
def locsplit(netloc, *, missing_as_none=False):
    return dict(zip(('username', 'password', 'hostname', 'port'), locsplit_to_tuple(netloc, missing_as_none=missing_as_none)))

@micropython.viper
def _is_scheme(buf_ptr: ptr8, start: int, colon: int) -> bool:
    if start >= colon:
        return False
    x = buf_ptr[start]
    if x < 65 or (x > 90 and x < 97) or x > 122:
        return False
    start += 1
    while start < colon:
        x = buf_ptr[start]
        start += 1
        if (not (48 <= x and x <= 57)
            and not (65 <= x and x <= 90)
            and not (97 <= x and x <= 122)
            and x != 43
            and x != 45
            and x != 46
        ):
            return False
    return True

def _check_authority(netloc, ss):
    if not netloc:
        return
    at = netloc.rfind('@' if ss else b'@') + 1
    lb = netloc.find('[' if ss else b'[', at)
    rb = netloc.find(']' if ss else b']', at)
    if ((lb < 0) ^ (rb < 0) or (
            lb >= 0 and (
                lb != at or
                rb <= lb + 1 or
                (rb + 1 < len(netloc) and
                 not netloc.startswith(':' if ss else b':', rb + 1))
            ))):
        raise ValueError("bad IPv6 authority")

def urlsplit_to_tuple(url, scheme=None, allow_fragments=True, *, missing_as_none=False):
    if url is None:
        url = b"" if isinstance(scheme, (bytes, bytearray)) else ""
    ss = isinstance(url, str)
    missing = None if missing_as_none else "" if ss else b""
    if scheme is None:
        scheme = missing
    elif isinstance(url, str) ^ isinstance(scheme, str):
        if scheme:
            raise TypeError("arguments must be similar types")
        scheme = missing
    elif isinstance(scheme, bytearray):
        scheme = scheme[:]

    start = 0
    end = len(url)

    while start < end:
        if url[start] > (" " if ss else 32):
            break
        start += 1

    netloc = query = frag = missing
    if scheme is None:
        scheme = missing

    if allow_fragments and (i := url.find('#' if ss else b'#', start)) >= 0:
        frag = url[i+1:]
        end = i

    if (i := url.find('?' if ss else b'?', start)) >= 0 and i < end:
        query = url[i+1:end]
        end = i

    colon = url.find(':' if ss else b':', start)
    if start < colon < end and _is_scheme(url, start, colon):
        slash = url.find('/' if ss else b'/', start)
        if slash < 0 or colon < slash:
            scheme = url[start:colon].lower()
            start = colon + 1

    if url.startswith("//" if ss else b"//", start):
        start += 2
        slash = url.find('/' if ss else b'/', start)
        delim = slash if (0 <= slash < end) else end
        netloc = url[start:delim]
        start = delim

    _check_authority(netloc, ss)

    return (scheme, netloc, url[start:end], query, frag)

class SplitResult(tuple):

    def __init__(self, scheme, netloc, path, query, frag):
        super().__init__((scheme, netloc, path, query, frag))
        self._locsplit_ = None
        if not isinstance(netloc, (str, bytes)):
            self._locsplit
        self._keep_empty = False

    @property
    def _locsplit(self):
        if self._locsplit_ is None:
            self._locsplit_ = locsplit_to_tuple(self[1], missing_as_none=True)
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
        if port == ":" or port == b":":
            return None
        raise ValueError("bad port number")

    def geturl(self):
        return urlunsplit(self)

keep_def urlsplit(url, scheme=None, allow_fragments=True, *, missing_as_none=False):
    res = SplitResult(*urlsplit_to_tuple(url, scheme, allow_fragments, missing_as_none=missing_as_none))
    return res

def _urlunsplit(scheme, netloc, path, query, frag):
    ss = isinstance(path, str)

    parts = []

    if scheme:
        parts.append(scheme)
        parts.append(":" if ss else b":")

    if netloc is not None:
        parts.append("//" if ss else b"//")
        parts.append(netloc)
        if path and not path.startswith("/" if ss else b"/"):
            parts.append("/" if ss else b"/")
    else:
        if path and path.startswith("//" if ss else b"//"):
            parts.append("//" if ss else b"//")

    if path:
        parts.append(path)

    if query is not None:
        parts.append("?" if ss else b"?")
        parts.append(query)

    if frag is not None:
        parts.append("#" if ss else b"#")
        parts.append(frag)

    return ("" if ss else b"").join(parts)

def urlunsplit(components, *, keep_empty=None):
    if keep_empty is None:
        keep_empty = getattr(components, "_keep_empty", False)

    scheme, netloc, path, query, frag = components
    ss = isinstance(path, str)

    if not keep_empty:
        if not scheme:
            scheme = None

        if not netloc:
            network_scheme = scheme
            if network_scheme and not isinstance(network_scheme, str):
                network_scheme = network_scheme.decode()

            if (network_scheme in _USES_NETLOC and
                    (not path or path.startswith("/" if ss else b"/"))):
                netloc = "" if ss else b""
            else:
                netloc = None

        if not query:
            query = None
        if not frag:
            frag = None

    return _urlunsplit(scheme, netloc, path, query, frag)

def _urlencode_generator(query, doseq, safe, quote_via, equals):
    if hasattr(query, "items"):
        query = query.items()
    for item in query:
        if not isinstance(item, (list, tuple)) or len(item) != 2:
            raise TypeError("query item is not a key-value pair")
        key, val = item
        if not isinstance(key, (str, bytes, bytearray)):
            key = str(key)
        key = quote_via(key, safe)

        if not isinstance(val, (str, bytes, bytearray)):
            if doseq and not isinstance(val, memoryview):
                try: len(val)
                except TypeError: pass
                else:
                    for v in val:
                        if not isinstance(v, (str, bytes, bytearray)):
                            v = str(v)
                        yield key + equals + quote_via(v, safe)
                    continue
            val = str(val)
        yield key + equals + quote_via(val, safe)

def urlencode(query, doseq=False, safe="", quote_via=quote_plus):
    if quote_via is quote_plus or quote_via is quote:
        if safe and not isinstance(safe, _compiled_safe):
            safe = compile_safe(safe, 1 if quote_via is quote_plus else 0)
        separator, equals = "&", "="
    elif quote_via is quote_plus_to_bytes or quote_via is quote_to_bytes:
        if safe and not isinstance(safe, _compiled_safe):
            safe = compile_safe(safe, 1 if quote_via is quote_plus_to_bytes else 0)
        separator, equals = b"&", b"="
    elif isinstance(quote_via(""), str):
        separator, equals = "&", "="
    else:
        separator, equals = b"&", b"="

    return separator.join(
        _urlencode_generator(
            query,
            doseq,
            safe,
            quote_via,
            equals,
        )
    )

@micropython.viper
def _parse_helper(mv: ptr8, start: int, end: int, separator: int) -> object:
    equals = -1
    i = start
    while i < end:
        b = mv[i]
        if b == separator:
            return (equals, i)
        if b == 61 and equals < 0:
            equals = i
        i += 1
    return (equals, end)

def _parse_generator(s, *, keep_blank_values=False, strict_parsing=False,
                     errors="ignore", max_num_fields=None, separator='&'):
    if s is None:
        return
    if isinstance(s, str):
        src = memoryview(s)
        do_decode = True
    else:
        src = s
        do_decode = False
    srclen = len(src)
    if srclen == 0:
        return

    try: sep = ord(separator)
    except TypeError: sep = -1
    if not (0 <= sep <= (127 if do_decode else 255)):
        raise ValueError("invalid separator")
    i = 0
    num_fields = 0

    while i <= srclen:
        if max_num_fields is not None:
            num_fields += 1
            if num_fields > max_num_fields:
                raise ValueError("Max number of fields exceeded")
        eq, j = _parse_helper(src, i, srclen, sep)
        if i == j:
            if strict_parsing:
                raise ValueError("bad query field")
            i = j + 1
            continue

        if eq < 0:
            if strict_parsing:
                raise ValueError("bad query field")
            if not keep_blank_values:
                i = j + 1
                continue
            eq = j
            val = b""
        else:
            if not keep_blank_values and eq + 1 == j:
                i = j + 1
                continue
            val = _unquote(src, eq + 1, j, True)

        key = _unquote(src, i, eq, True)

        try:
            if do_decode:
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

def parse_qs(qs, *args, **kwargs):
    res = {}
    for key, val in _parse_generator(qs, *args, **kwargs):
        values = res.get(key)
        if values is None:
            res[key] = [val]
        else:
            values.append(val)
    return res

def parse_qsl(qs, *args, **kwargs):
    return list(_parse_generator(qs, *args, **kwargs))

def urldecode(qs, *args, **kwargs):
    res = {}
    for key, val in _parse_generator(qs, *args, **kwargs):
        res[key] = val
    return res

def urldefrag_to_tuple(url):
    ss = isinstance(url, str)

    hmark = url.find("#" if ss else b"#")
    if hmark >= 0:
        return (url[:hmark], url[hmark + 1:])
    return (url, "" if ss else b"")

urldefrag = urldefrag_to_tuple

# Derived from CPython (all bugs are mine)
def urljoin(base, url, allow_fragments=True):
    if not base:
        return url
    if not url:
        return base
    if isinstance(base, str) ^ isinstance(url, str):
        raise TypeError("arguments must be similar types")

    ss = isinstance(base, str)
    if not ss:
        base = base.decode()
        url = url.decode()

    bscheme, bnetloc, bpath, bquery, bfrag = urlsplit_to_tuple(base, None, allow_fragments, missing_as_none=True)
    scheme, netloc, path, query, frag = urlsplit_to_tuple(url, None, allow_fragments, missing_as_none=True)

    if scheme is None:
        scheme = bscheme
    if scheme != bscheme or (scheme and scheme not in _USES_RELATIVE):
        return url if ss else url.encode()
    if not scheme or scheme in _USES_NETLOC:
        if netloc:
            res = _urlunsplit(scheme, netloc, path, query, frag)
            return res if ss else res.encode()
        netloc = bnetloc

    if not path:
        path = bpath
        if query is None:
            query = bquery
            if frag is None:
                frag = bfrag
        res = _urlunsplit(scheme, netloc, path, query, frag)
        return res if ss else res.encode()

    base_parts = bpath.split('/')
    if base_parts[-1]:
        # the last item is not a directory, so will not be taken into account
        # in resolving the relative path
        del base_parts[-1]

    # for rfc3986, ignore all base path should the first character be root.
    if path.startswith('/'): # `not path` was already checked earlier
        segments = path.split('/')
    else:
        segments = base_parts
        segments.extend(path.split("/"))
        # Remove empty segments in the middle (keep first and last as-is)
        w = 1
        for r in range(1, len(segments) - 1):
            seg = segments[r]
            if seg:
                segments[w] = seg
                w += 1
        # delete the now-unused tail (but preserve the last element)
        del segments[w:len(segments) - 1]

    w = 0
    for seg in segments:
        if seg == "..":
            if w:
                w -= 1
        elif seg != ".":
            segments[w] = seg
            w += 1

    if segments[-1] in (".", ".."):
        segments[w] = ""
        w += 1

    del segments[w:]

    res = _urlunsplit(
        scheme,
        netloc,
        "/".join(segments) or "/",
        query,
        frag,
    )
    return res if ss else res.encode()
