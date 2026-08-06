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
    b"\x00\x60\xff\x03"  # 0-9, -, .
    b"\xfe\xff\xff\x87"  # A-Z, _
    b"\xfe\xff\xff\x07"  # a-z
)
_COMPILED_SLASH = (
    b"\x00\x00\x00\x69"
    b"\x00\xe0\xff\x03"  # slash
    b"\xfe\xff\xff\x87"
    b"\xfe\xff\xff\x07"
)
_COMPILED_PLUS = (
    b"\x01\x00\x00\x69"  # plus mode
    b"\x00\x60\xff\x03"
    b"\xfe\xff\xff\x87"
    b"\xfe\xff\xff\x07"
)

class _compiled_blob(bytearray):
    def __init__(self):
        super().__init__(_COMPILED_EMPTY)

def compile_safe(safe, flags=0):
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
def _quote_helper(src: ptr8, srclen: int, safeblob_obj: object, res: ptr8) -> int:
    safeblob = ptr8(safeblob_obj)
    write = int(res) != 0
    flags = safeblob[0]

    if (flags != 0 and flags != 1) or safeblob[3] != 0x69:
        return -999

    hex_digits = ptr8(_HEX_DIGITS)
    modified = 0
    reslen = 0
    i = 0

    while i < srclen:
        b = src[i]
        i += 1

        if b == 32 and flags:
            modified = 1
            if write:
                res[reslen] = 43
            reslen += 1
            continue

        if 32 <= b and b < 128:
            is_safe = (safeblob[b >> 3] >> (b & 7)) & 1
        else:
            is_safe = 0

        if is_safe:
            if write:
                res[reslen] = b
            reslen += 1
        else:
            modified = 1
            if write:
                res[reslen] = 37
                res[reslen + 1] = hex_digits[b >> 4]
                res[reslen + 2] = hex_digits[b & 15]
            reslen += 3

    return reslen if modified else -1

def _quote(src, safe, flags):
    srclen = len(src)
    compiled = isinstance(safe, _compiled_blob)

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
        return res.decode()
    else:
        res = _quote(s, safe, 0)
        if res is None:
            res = s
            if isinstance(res, memoryview):
                res = bytes(res)
        return res.decode()

def quote_plus(s, safe=""):
    if isinstance(s, str):
        res = _quote(memoryview(s), safe, 1)
        if res is None:
            return s
        return res.decode()
    else:
        res = _quote(s, safe, 1)
        if res is None:
            res = s
            if isinstance(res, memoryview):
                res = bytes(res)
        return res.decode()

def quote_from_bytes(bs, safe="/"):
    if not isinstance(bs, (bytes, bytearray)):
        raise TypeError("bytes required")
    return quote(bs, safe)

def quote_to_bytes(s, safe="/"):
    if isinstance(s, str):
        res = _quote(memoryview(s), safe, 0)
        if res is None:
            return s.encode()
        return res
    else:
        res = _quote(s, safe, 0)
        if res is None:
            res = s
            if isinstance(res, memoryview):
                res = bytes(res)
        return res

@micropython.viper
def _unquote_helper(src: ptr8, start: int, end: int, res: ptr8) -> int:
    if end < 0:
        end = -end
        plusmode = 1
    else:
        plusmode = 0
    write = int(res) != 0

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

        if write:
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
    return _unquote(s, 0, None, False)

# Extension
def locsplit_to_tuple(netloc, *, missing_as_none=False):
    ss = isinstance(netloc, str)
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
    elif (sep := hostport.rfind(':' if ss else b':')) >= 0:
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

def urlsplit_to_tuple(url, scheme=None, allow_fragments=True, *, missing_as_none=False):
    if url is None:
        url = ""
    if scheme and (isinstance(url, str) ^ isinstance(scheme, str)):
        raise TypeError("arguments must be similar types")
    ss = isinstance(url, str)
    missing = None if missing_as_none else "" if ss else b""

    starts = 0
    finish = len(url)

    for i in range(finish):
        if url[i] <= (" " if ss else 32):
            starts = i + 1
        else:
            break

    netloc = query = frag = missing
    if scheme is None:
        scheme = missing

    if allow_fragments and (i := url.find('#' if ss else b'#', starts)) >= 0:
        frag = url[i+1:]
        finish = i

    if (i := url.find('?' if ss else b'?', starts)) >= 0 and i < finish:
        query = url[i+1:finish]
        finish = i

    colon = url.find(':' if ss else b':', starts)
    if starts < colon < finish and url[starts:starts+1].isalpha():
        slash = url.find('/' if ss else b'/', starts)
        if slash < 0 or colon < slash:
            scheme = url[starts:colon].lower()
            starts = colon + 1

    if url.startswith("//" if ss else b"//", starts):
        starts += 2
        slash = url.find('/' if ss else b'/', starts)
        delim = slash if (0 <= slash < finish) else finish
        netloc = url[starts:delim]
        starts = delim

    if netloc and (i := netloc.find('[' if ss else b'[')) >= 0:
        if not (netloc.rfind('@' if ss else b'@') + 1 == i < netloc.find(']' if ss else b']')):
            raise ValueError("bad IPv6 address")

    return (scheme, netloc, url[starts:finish], query, frag)

class SplitResult(tuple):

    def __init__(self, scheme, netloc, path, query, frag):
        super().__init__((scheme, netloc, path, query, frag))
        self._keep_empty = False
        self._locsplit_ = None

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

def urlsplit(url, scheme=None, allow_fragments=True, *, missing_as_none=False):
    res = SplitResult(*urlsplit_to_tuple(url, scheme, allow_fragments, missing_as_none=missing_as_none))
    if missing_as_none:
        res._keep_empty = True
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
    bytes_like = (str, bytes, bytearray)

    if hasattr(query, "items"):
        query = query.items()
    for key, val in query:
        if not isinstance(key, bytes_like):
            key = str(key)
        key = quote_via(key, safe)

        if not isinstance(val, bytes_like):
            if doseq and not isinstance(val, memoryview):
                try: len(val)
                except TypeError: pass
                else:
                    for v in val:
                        if not isinstance(v, bytes_like):
                            v = str(v)
                        yield key + equals + quote_via(v, safe)
                    continue
            val = str(val)
        yield key + equals + quote_via(val, safe)

def urlencode(query, doseq=False, safe="", quote_via=quote_plus):
    if quote_via is quote_plus or isinstance(quote_via(""), str):
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
def _mv_find(mv: ptr8, b: int, start: int, end: int) -> int:
    i = start
    while i < end:
        if mv[i] == b:
            return i
        i += 1
    return -1

def _parse_generator(s, *, keep_blank_values=False, strict_parsing=False,
                     errors="ignore", max_num_fields=None, separator='&'):
    if s is None:
        return
    if isinstance(s, str):
        # on micropython, memoryview(str) gives you direct access to the underlying bytes
        src = memoryview(s)
        do_decode = True
    else:
        src = s
        do_decode = False
    srclen = len(src)
    if srclen == 0:
        return

    try: sep = ord(separator)
    except TypeError: raise ValueError("invalid separator")
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

        eq = _mv_find(src, 61, i, j)

        try:
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
        if key in res:
            res[key].append(val)
        else:
            res[key] = [val]
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
