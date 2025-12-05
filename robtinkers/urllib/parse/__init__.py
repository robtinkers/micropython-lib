# robtinkers/urllib.parse

__all__ = [
    "quote", "quote_from_bytes", "quote_plus", "unquote", "unquote_plus",
    "urlsplit", "netlocsplit", "netlocdict", "urlunsplit", "urljoin",
    "urlencode", "parse_qs", "parse_qsl", "urldecode", 
]

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

_safe_set = frozenset([45, 46, 95, 126]) # -._~
_safe_set_with_slash = frozenset([45, 46, 95, 126, 47]) # -._~/

_HEXDIGITS = b'0123456789ABCDEF'

def quote(s, safe='/', *, _plus=False) -> str:
    if not s:
        return ''
    
    if safe == '/':
        safe_bytes = _safe_set_with_slash
    elif safe == '':
        safe_bytes = _safe_set
    elif isinstance(safe, (set, frozenset)): # extension (should be a set of byte-values)
        safe_bytes = safe
    elif isinstance(safe, str):
        safe_bytes = set(_safe_set).union(set(ord(c) for c in safe))
    else:
        safe_bytes = set(_safe_set).union(set(b for b in safe))
    
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
            res[j+1] = _HEXDIGITS[(b >> 4) & 0xF]
            res[j+2] = _HEXDIGITS[(b >> 0) & 0xF]
            j += 3
    
    return res.decode('ascii') # can raise UnicodeError


quote_from_bytes = quote


def quote_plus(s, safe='') -> str:
    return quote(s, safe, _plus=True)


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
        raise ValueError('url must be a string')
    
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
        if colon > 0 and (slash == -1 or slash > colon) and url[0].isalpha():
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
        raise ValueError('netloc must be a string')
    
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


def urlunsplit(components:tuple) -> str:
    scheme, netloc, url, query, fragment = components
    if netloc:
        if url and url[:1] != '/':
            url = '/' + url
        url = '//' + netloc + url
    if scheme:
        url = scheme + ':' + url
    if query:
        url = url + '?' + query
    if fragment:
        url = url + '#' + fragment
    return url


def _normalize_path(path):
    if not path:
        return ''
    
    stack = []
    is_abs = path.startswith('/')
    
    start = 0
    while True:
        end = path.find('/', start)
        if end == -1:
            segment = path[start:]
        else:
            segment = path[start:end]
        
        if segment == '..':
            if stack and stack[-1] != '..':
                stack.pop()
            elif not is_abs:
                stack.append('..')
        elif segment != '.' and segment != '':
            stack.append(segment)
        
        if end == -1:
            break
        start = end + 1
    
    if is_abs:
        return '/' + '/'.join(stack)
    return '/'.join(stack) or '.'

def urljoin(base:str, url:str, allow_fragments=True) -> str:
    if not isinstance(base, str):
        raise ValueError('base must be a string')
    if not isinstance(url, str):
        raise ValueError('url must be a string')
    
    if base == '':
        return url
    if url == '':
        return base
    
    bs, bn, bp, bq, bf = urlsplit(base, '', allow_fragments)
    us, un, up, uq, uf = urlsplit(url, '', allow_fragments)
    
    if us != '' and us != bs:
        return url
    
    s, n, p, q, f = bs, bn, up, uq, uf
    
    if un != '':
        n = un
    elif up == '':
        # Empty path
        p = bp
        if uq == '':
            q = bq
            if uf == '':
                f = bf
    elif up.startswith('/'):
        # Absolute path
        pass # p is already up
    elif bp == '' or bp.endswith('/'):
        # Relative path - ...
        p = bp + up
    else:
        i = bp.rfind('/')
        if i != -1:
            # Relative path - ...
            p = bp[:i+1] + up
    
    return urlunsplit((s, n, _normalize_path(p), q, f))


def urlencode(query, doseq=False, safe='', quote_via=quote_plus) -> str:
    return '&'.join(
        (quote_via(str(key), safe) + '=' + quote_via(str(v), safe))
        for key, val in (query.items() if hasattr(query, 'items') else query)
        for v in (val if doseq else (val,))
    )


def _parse_qs_generator(qs:str, keep_blank_values=False, strict_parsing=False, unquote_via=unquote_plus):
    if not qs:
        return
        
    i = 0
    n = len(qs)
    
    while i < n:
        j = qs.find('&', i)
        if j == -1:
            j = n
        
        eq = qs.find('=', i, j)
        
        if eq == -1:
            if strict_parsing:
                raise ValueError("bad query field: %r" % (qs[i:j],))
            key = unquote_via(qs[i:j])
            val = ''
        else:
            key = unquote_via(qs[i:eq])
            val = unquote_via(qs[eq+1:j])
            
        if val or keep_blank_values:
            yield key, val
            
        i = j + 1

def parse_qs(qs:str, **kwargs) -> dict:
    res = {}
    for key, val in _parse_qs_generator(qs, **kwargs):
        if key in res:
            res[key].append(val)
        else:
            res[key] = [val]
    return res

def parse_qsl(qs:str, **kwargs) -> list:
    return list(_parse_qs_generator(qs, **kwargs))

def urldecode(qs:str, **kwargs) -> dict:
    res = {}
    for key, val in _parse_qs_generator(qs, **kwargs):
        res[key] = val
    return res

