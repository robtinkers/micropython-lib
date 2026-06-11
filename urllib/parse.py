# urllib/parse.py

import micropython
from array import array
from uctypes import addressof

_USES_RELATIVE = frozenset([
    "", "file", "ftp", "http", "https", "rtsp", "rtsps", "sftp", "ws", "wss",
])

#_USES_NETLOC = frozenset([
#    "", "file", "ftp", "http", "https", "rtsp", "rtsps", "sftp", "ws", "wss",
#])
_USES_NETLOC = _USES_RELATIVE

_HEX_DIGITS = b"0123456789ABCDEF"

# Standard safeblob for ASCII 32-127
# 0-31:   not used
# 32-63:  0-9, -, .
_COMPILED_BASE1 = const(0x03FF6000)
# 64-95:  A-Z, _
_COMPILED_BASE2 = const(0x87FFFFFE)
# 96-127: a-z, ~
_COMPILED_BASE3 = const(0x47FFFFFE)

_COMPILED_EMPTY = array('I', [
    0,
    _COMPILED_BASE1, 
    _COMPILED_BASE2, 
    _COMPILED_BASE3
])

_COMPILED_SLASH = array('I', [
    0,
    _COMPILED_BASE1 | (1 << 15), # slash
    _COMPILED_BASE2, 
    _COMPILED_BASE3
])

_COMPILED_PLUS = array('I', [
    1, # plus mode
    _COMPILED_BASE1, 
    _COMPILED_BASE2, 
    _COMPILED_BASE3
])

@micropython.viper
def _quote_helper(src: ptr8, srclen: int, safeblob_obj: object, out: ptr8) -> int:
    safeblob = ptr32(safeblob_obj)
    write = int(out) != 0
    modified = 0
    outlen = 0
    b = 0
    
    # Unpack safeblob into local variables for speed
    flags = safeblob[0]
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

def compile_safe(safe, flags=0):
    safeblob = array('I', [flags, _COMPILED_BASE1, _COMPILED_BASE2, _COMPILED_BASE3])
    for c in safe:
        if isinstance(c, str):
            c = ord(c)
        if 32 <= c <= 127:
            safeblob[(c >> 5)] |= (1 << (c & 31))
    return safeblob

def _quote(s, safeblob):
    if isinstance(s, (memoryview, bytes, bytearray)):
        src = s
#    elif isinstance(s, str):
#        src = s.encode()
    else:
        # on micropython, memoryview(str) gives you direct access to the underlying bytes
        # if this doesn't work for some reason, enable the 'elif' code above
        src = memoryview(s)
    
    srclen = len(src)
    if srclen == 0:
        return ""
    
    outlen = _quote_helper(src, srclen, safeblob, 0)
    if outlen <= 0:
        if isinstance(s, str):
            return s
        elif isinstance(s, (bytes, bytearray)):
            return s.decode("ascii")
        else:
            return bytes(s).decode("ascii")
    
    out = bytearray(outlen)
    _quote_helper(src, srclen, safeblob, out)
    return out.decode("ascii")

def quote(s, safe="/"):
    if safe == "/":
        return _quote(s, _COMPILED_SLASH)
    elif safe == "":
        return _quote(s, _COMPILED_EMPTY)
    elif isinstance(safe, array):
        safe[0] = 0
        return _quote(s, safe)
    else:
        return _quote(s, compile_safe(safe, 0))

def quote_plus(s, safe=""):
    if safe == "":
        return _quote(s, _COMPILED_PLUS)
    elif isinstance(safe, array):
        safe[0] = 1
        return _quote(s, safe)
    else:
        return _quote(s, compile_safe(safe, 1))

def quote_from_bytes(bs, safe="/"):
    if not isinstance(bs, (bytes, bytearray)):
        raise TypeError("quote_from_bytes() expected bytes")
    if safe == "/":
        return _quote(bs, _COMPILED_SLASH)
    elif safe == "":
        return _quote(bs, _COMPILED_EMPTY)
    elif isinstance(safe, array):
        safe[0] = 0
        return _quote(bs, safe)
    else:
        return _quote(bs, compile_safe(safe, 0))



_HEX_TO_INT = const(b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\xff\xff\xff\xff\xff\xff\xff\x0a\x0b\x0c\x0d\x0e\x0f\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x0a\x0b\x0c\x0d\x0e\x0f\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff")

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
    n1 = n2 = b = 0
    
    hex_to_int = ptr8(_HEX_TO_INT)
    
    i = start
    while (i < end):
        b = src[i]
        i += 1
        
        if b == 37: # '%'
            if (i + 1 < end):
#                n1 = src[i+0]
#                if   48 <= n1 <= 57: n1 -= 48
#                elif 65 <= n1 <= 70: n1 -= 55
#                elif 97 <= n1 <=102: n1 -= 87
#                else: n1 = 255
                n1 = hex_to_int[src[i+0]]
                
#                n2 = src[i+1]
#                if   48 <= n2 <= 57: n2 -= 48
#                elif 65 <= n2 <= 70: n2 -= 55
#                elif 97 <= n2 <=102: n2 -= 87
#                else: n2 = 255
                n2 = hex_to_int[src[i+1]]
            else:
                n1 = 255
                n2 = 255
            
            if n1 != 255 and n2 != 255:
                modified = 1
                b = (n1 << 4) | (n2 << 0)
                i += 2
        
        elif b == 43 and plusmode: # '+'
            modified = 1
            b = 32 # space
        
        if write:
            out[outlen] = b
        outlen += 1
    
    return outlen if modified else -outlen

def _unquote(src, start, end, plusmode: int) -> bytes:
    if isinstance(src, str):
        # on micropython, memoryview(str) gives you direct access to the underlying bytes
        # but you're going to have a hard time unless (start == 0 and end is None)
        assert(start == 0 and end is None)
        src = memoryview(src)
        end = srclen = len(src)
    else:
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
        return bytes(out)
    
    if start != 0 or end != srclen:
        out = src[start:end]
    else:
        out = src
    
    if not isinstance(out, bytes):
        out = bytes(out)
    return out

def unquote(s):
    return _unquote(s, 0, None, 0).decode()

def unquote_plus(s):
    return _unquote(s, 0, None, 1).decode()

def unquote_to_bytes(s) -> bytes:
    return _unquote(s, 0, None, 0)



def _urlencode_generator(query, doseq=False, safe="", quote_via=quote_plus):
    if isinstance(query, dict):
        query = query.items()
    for key, val in query:
        if not isinstance(key, (str, bytes, bytearray, memoryview)):
            key = str(key)
        key = quote_via(key, safe)
        if doseq:
            for v in val:
                if not isinstance(v, (str, bytes, bytearray, memoryview)):
                    v = str(v)
                yield key + "=" + quote_via(v, safe)
            continue
        elif not isinstance(val, (str, bytes, bytearray, memoryview)):
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

def _parse_generator(src, keep_blank_values=False, strict_parsing=False,
                     errors="ignore", separator='&', _decode=True):
    if isinstance(src, str):
        # on micropython, memoryview(str) gives you direct access to the underlying bytes
        src = memoryview(src)
    srclen = len(src)
    if srclen == 0:
        return
    
    sep = ord(separator)  # works if separator is string-like length 1; otherwise error
    i = 0
    
    while i <= srclen:
        j = _mv_find(src, sep, i, srclen)
        if j < 0:
            j = srclen
        eq = _mv_find(src, 61, i, j) # '='
        
        try:
            if eq < 0:
                # key (no '=')
                if strict_parsing:
                    raise ValueError("bad query field")
                if keep_blank_values and i < j: # empty segments are skipped, not blank
                    key = _unquote(src, i, j, 1)
                    val = b""
                    if _decode:
                        key = key.decode()
                        val = ""
                    yield key, val
            else:
                # key=value
                if keep_blank_values or (eq + 1 < j):
                    key = _unquote(src, i, eq, 1)
                    val = _unquote(src, eq + 1, j, 1)
                    if _decode:
                        key = key.decode()
                        val = val.decode() 
                    yield key, val
        except UnicodeError:
            if errors != "ignore":
                raise
        
        i = j + 1

def parse_qs(qs, *args, **kwargs) -> dict:
    kwargs['_decode'] = isinstance(qs, str)
    out = {}
    for key, val in _parse_generator(qs, *args, **kwargs):
        if key in out:
            out[key].append(val)
        else:
            out[key] = [val]
    return out

def parse_qsl(qs, *args, **kwargs) -> list:
    kwargs['_decode'] = isinstance(qs, str)
    return list(_parse_generator(qs, *args, **kwargs))

def urldecode(qs, *args, **kwargs) -> dict:
    kwargs['_decode'] = isinstance(qs, str)
    out = {}
    for key, val in _parse_generator(qs, *args, **kwargs):
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
#    assert (isinstance(url, str))
    
    # url = url.lstrip()
    start, end = 0, len(url)
    while start < end and ord(url[start]) <= 32: start += 1
    if start > 0:
        url = url[start:]
    
    # scheme = scheme.strip()
    if scheme:
        start, end = 0, len(scheme)
        while start < end and ord(scheme[start]) <= 32: start += 1
        while end > start and ord(scheme[end - 1]) <= 32: end -= 1
        if start > 0 or end < len(scheme):
            scheme = scheme[start:end]
    
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
        self.username, self.password, self.hostname, self._port = locsplit_as_tuple(self[1])
    
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
    def port(self):
        if isinstance(self._port, int):
            return self._port
        if not self._port or self._port == ":":
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
