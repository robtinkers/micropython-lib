# robtinkers/urllib.parse

__all__ = [
    "quote", "quote_from_bytes", "quote_plus", "unquote", "unquote_plus",
    "urlsplit", "netlocsplit", "netlocdict", "urlunsplit", "urljoin",
    "urlencode", "parse_qs", "parse_qsl", "urldecode", 
]

_USES_NETLOC = frozenset(['file', 'ftp', 'http', 'https', 'ws', 'wss'])

_ASCIITABLE = (
    # bit7: isupper
    # bit6: islower
    # bit5: isdigit
    # bit4: ishex
    # bits3-0: hex
    b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    b'\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x00\x00\x00\x00\x00\x00' # 0-9
    b'\x00\x9a\x9b\x9c\x9d\x9e\x9f\x80\x80\x80\x80\x80\x80\x80\x80\x80' # A-O
    b'\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x00\x00\x00\x00\x00' # P-Z
    b'\x00\x5a\x5b\x5c\x5d\x5e\x5f\x40\x40\x40\x40\x40\x40\x40\x40\x40' # a-o
    b'\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x00\x00\x00\x00\x00' # p-z
    b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
)

_HEXNIBBLE = b'0123456789ABCDEF'

_SAFE_SET = frozenset([45, 46, 95, 126]) # -._~
_SAFE_SET_WITH_SLASH = frozenset([45, 46, 95, 126, 47]) # -._~/


def quote(s, safe='/', *, _plus=False) -> str:
    if not s:
        return ''
    
    if safe == '/':
        safe_bytes = _SAFE_SET_WITH_SLASH
    elif safe == '':
        safe_bytes = _SAFE_SET
    elif isinstance(safe, (set, frozenset)): # extension (should be a set of byte-values)
        safe_bytes = safe
    elif isinstance(safe, str):
        safe_bytes = set(_SAFE_SET).union(set(ord(c) for c in safe))
    else:
        safe_bytes = set(_SAFE_SET).union(set(b for b in safe))
    
    bmv = memoryview(s) # In micropython, memoryview(str) returns read-only UTF-8 bytes
    
    # First pass: check for fast path (no quotes) and calculate length of the result
    
    m = 0
    fast = True
    for b in bmv:
        if (_ASCIITABLE[b] & 0xE0) or (b in safe_bytes):
            m += 1
        elif b == 32 and _plus:
            m += 1
            fast = False
        else:
            m += 3
            fast = False
    if fast:
        return s if isinstance(s, str) else s.decode('ascii')
    
    # Second pass:
    
    res = bytearray(m) # we just calculated the length of the result
    j = 0
    
    for b in bmv:
        if (_ASCIITABLE[b] & 0xE0) or (b in safe_bytes):
            res[j] = b
            j += 1
        elif b == 32 and _plus:
            res[j] = 43 # +
            j += 1
        else:
            res[j+0] = 37 # %
            res[j+1] = _HEXNIBBLE[(b >> 4) & 0xF]
            res[j+2] = _HEXNIBBLE[(b >> 0) & 0xF]
            j += 3
    
    return res.decode('ascii') # can raise UnicodeError


quote_from_bytes = quote


def quote_plus(s, safe='') -> str:
    return quote(s, safe=safe, _plus=True)


def unquote(s, *, _plus=False) -> str:
    if not s:
        return ''
    
    bmv = memoryview(s) # In micropython, memoryview(str) returns read-only UTF-8 bytes
    n = len(bmv)
    
    # First pass: check for fast path (no quotes)
    
    fast = True
    for b in bmv:
        if (b == 37) or (b == 43 and _plus):
            fast = False
            break
    if fast:
        return s if isinstance(s, str) else str(s, 'utf-8')
    
    # Second pass:
    
    res = bytearray(n) # Worst Case: result is the same size as the input
    j = 0
    
    i = 0
    while (i < n):
        b = bmv[i]
        i += 1
        
        if b == 37:
            # Found '%'
            if (i + 1 < n):
                n1 = _ASCIITABLE[bmv[i+0]]
                n1 = (n1 & 0x0F) if (n1 & 0x10) else -1
                n2 = _ASCIITABLE[bmv[i+1]]
                n2 = (n2 & 0x0F) if (n2 & 0x10) else -1
            else:
                n1 = n2 = -1
            if n1 >= 0 and n2 >= 0:
                res[j] = (n1 << 4) | (n2 << 0)
                i += 2
            else:
                res[j] = 37 # percent
        elif b == 43 and _plus:
            # Found '+' and _plus
            res[j] = 32 # space
        else:
            res[j] = b
        
        j += 1
    
    return str(memoryview(res)[:j], 'utf-8') # can raise UnicodeError


def unquote_plus(s) -> str:
    return unquote(s, _plus=True)


def urlsplit(url:str, scheme='', allow_fragments=True) -> tuple:
    if not isinstance(url, str):
        raise TypeError('url must be a string')
    
    if len(url) > 0 and ord(url[0]) <= 32:
        url = url.lstrip() # CPython always does lstrip()
    netloc = query = fragment = ''
    if allow_fragments:
        url, _, fragment = url.partition('#')
    url, _, query = url.partition('?')
    
    if url.startswith('//'):
        url = url[2:]
        netloc, sep, path = url.partition('/')
        if sep or path:
             path = '/' + path
    elif url.startswith('/'):
        path = url
    else:
        colon = url.find(':')
        slash = url.find('/')
        # Scheme exists if colon is present and comes before any slash
        if (colon > 0 and url[0].isalpha()) and (slash == -1 or slash > colon):
            scheme = url[:colon].lower()
            url = url[colon+1:]
            if url.startswith('//'):
                url = url[2:]
                netloc, sep, path = url.partition('/')
                if sep or path:
                    path = '/' + path
            else:
                path = url
        else:
            path = url
    
    return (scheme, netloc, path, query, fragment)


def netlocsplit(netloc:str) -> tuple: # extension
    if not isinstance(netloc, str):
        raise TypeError('netloc must be a string')
    
    userinfo, sep, hostport = netloc.rpartition('@')
    if sep:
        username, sep, password = userinfo.partition(':')
        if not sep:
            password = None
    else:
        hostport = netloc
        username, password = None, None
    
    if hostport.startswith('['):
        # IPv6
        close_bracket = hostport.find(']')
        if close_bracket > 0:
            hostname = hostport[1:close_bracket]
            # check for :port after the closing bracket
            if len(hostport) > close_bracket + 1 and hostport[close_bracket + 1] == ':':
                port = hostport[close_bracket + 2:]
            else:
                port = None
            # Don't lower-case IPv6 addresses because of %zone_info
        else:
            # Malformed IPv6 address (missing bracket)
            # Treat the whole string as the hostname
            hostname = hostport
            port = None
    else:
        # IPv4 or hostname
        hostname, sep, port = hostport.rpartition(':')
        if not sep:
            hostname, port = hostport, None
        elif not port:
            port = None
        if hostname:
            hostname = hostname.lower()
        else:
            hostname = None
    
    try:
        port = int(port, 10)
        if not (0 <= port): # CPython raises ValueError if out of range 0-65535
            port = None
    except (TypeError, ValueError):
        port = None
    
    return (username, password, hostname, port)


def netlocdict(netloc:str) -> dict: # extension
    return dict(zip(('username', 'password', 'hostname', 'port'), netlocsplit(netloc)))


def urlunsplit(components: tuple) -> str:
    scheme, netloc, url, query, fragment = components
    
    if netloc or (scheme in _USES_NETLOC):
        if url and url[:1] != '/': 
            url = '/' + url
        url = '//' + (netloc or '') + url
        
    if scheme:
        url = f"{scheme}:{url}"
    if query:
        url = f"{url}?{query}"
    if fragment:
        url = f"{url}#{fragment}"
    return url


def _normalize_path(path: str) -> str:
    if path == '' or path == '/':
        return path
    
    slashes = 0
    for char in path:
        if char == '/':
            slashes += 1
        else:
            break
    
    stack = []
    
    for seg in path.split('/'):
        if seg == '' or seg == '.':
            continue
        elif seg == '..':
            if stack and stack[-1] != '..':
                stack.pop()
            elif slashes == 0:
                stack.append('..')
        else:
            stack.append(seg)
    
    res = '/'.join(stack)
    
    if slashes > 0:
        res = ('/' * slashes) + res
    
    if path.endswith('/') or path.endswith('/.') or path.endswith('/..') or path == '.' or path == '..':
        if not res.endswith('/') and not (stack and stack[-1] == '..'):
            if res != '':
                res += '/'
    
    return res


def urljoin(base:str, url:str, allow_fragments=True) -> str:
    if not isinstance(base, str):
        raise TypeError('base must be a string')
    if not isinstance(url, str):
        raise TypeError('url must be a string')
    
    if base == '':
        return url
    if url == '':
        return base
    
    bs, bn, bp, bq, bf = urlsplit(base, '', allow_fragments)
    us, un, up, uq, uf = urlsplit(url, '', allow_fragments)
    
    if us:
        return url
    us = bs
    
    if un or url.startswith('//'):
        return urlunsplit((us, un, _normalize_path(up), uq, uf))
    un = bn
    
    if up:
        if not up.startswith('/'):
            if not bp:
                if bn:
                    up = '/' + up
            elif bp.endswith('/'):
                up = bp + up
            else:
                rs = bp.rfind('/')
                if rs != -1:
                    up = bp[:rs+1] + up
    else:
        up = bp
        if not uq:
            uq = bq
    
    return urlunsplit((us, un, _normalize_path(up), uq, uf))


def _urlencode_generator(query, doseq=False, safe='', *, quote_via=quote_plus):
    for key, val in (query.items() if hasattr(query, 'items') else query):
        if isinstance(key, (str, bytes, bytearray)):
            key = quote_via(key, safe)
        else:
            key = quote_via(str(key), safe)
        
        if isinstance(val, (str, bytes, bytearray)):
            val = quote_via(val, safe)
            yield f"{key}={val}"
        elif doseq: # trust the caller
            for v in val:
                if isinstance(v, (str, bytes, bytearray)):
                    v = quote_via(v, safe)
                else:
                    v = quote_via(str(v), safe)
                yield f"{key}={v}"
        else:
            val = quote_via(str(val), safe)
            yield f"{key}={val}"

def urlencode(query, *args, **kwargs) -> str:
    return '&'.join(_urlencode_generator(query, *args, **kwargs))


def _parse_qs_generator(qs:str, keep_blank_values=False, strict_parsing=False, unquote_via=unquote_plus):
    if not qs:
        return
        
    j = -1
    n = len(qs)
    
    while (j + 1) < n:
        i = j + 1
        j = qs.find('&', i)
        if j == -1:
            j = n
        
        eq = qs.find('=', i, j)
        
        if eq >= 0:
            if keep_blank_values or (eq + 1 < j):
                yield unquote_via(qs[i:eq]), unquote_via(qs[eq+1:j])
        else:
            if strict_parsing:
#                raise ValueError("bad query field: %r" % (qs[i:j],))
                continue # CPython raises ValueError, we silently drop
            if keep_blank_values:
                yield unquote_via(qs[i:j]), ''

def parse_qs(qs:str, *args, **kwargs) -> dict:
    res = {}
    for key, val in _parse_qs_generator(qs, *args, **kwargs):
        if key in res:
            res[key].append(val)
        else:
            res[key] = [val]
    return res

def parse_qsl(qs:str, *args, **kwargs) -> list:
    return list(_parse_qs_generator(qs, *args, **kwargs))

def urldecode(qs:str, *args, **kwargs) -> dict:
    res = {}
    for key, val in _parse_qs_generator(qs, *args, **kwargs):
        res[key] = val
    return res

