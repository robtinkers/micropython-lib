# robtinkers/urllib.parse

__all__ = [
    "quote", "quote_plus", "unquote", "unquote_plus",
    "urlsplit", "netlocsplit", "netlocdict", "urlunsplit", "urljoin",
    "urlencode", "parse_qs", "parse_qsl", "urldecode", 
]


_safe_set = frozenset([45, 46, 95, 126]) # -._~
_safe_set_with_slash = frozenset([45, 46, 95, 126, 47]) # -._~/

_hexdig = b'0123456789ABCDEF'

def quote(s, safe='/', *, _plus=False):
    if s == '':
        return s
    
    if safe == '/':
        safe_bytes = _safe_set_with_slash
    elif safe == '':
        safe_bytes = _safe_set
    elif isinstance(safe, (set, frozenset)): # extension (should be a set of byte-values)
        safe_bytes = safe
    else:
        safe_bytes = set(_safe_set) # creates a writeable copy
        safe_bytes.update(set(ord(c) for c in safe)) # safe characters must be ASCII
    
    bmv = memoryview(s) # In micropython, memoryview(str) returns read-only UTF-8 bytes
    
    # First pass: check for fast path (no quotes) and calculate length of the result
    
    m = 0
    fast = True
    for b in bmv:
        if (48 <= b <= 57) or (65 <= b <= 90) or (97 <= b <= 122) or (b in safe_bytes):
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
        if (48 <= b <= 57) or (65 <= b <= 90) or (97 <= b <= 122) or (b in safe_bytes):
            res[j] = b
            j += 1
        elif b == 32 and _plus:
            res[j] = 43 # +
            j += 1
        else:
            res[j+0] = 37 # %
            res[j+1] = _hexdig[(b >> 4) & 0xF]
            res[j+2] = _hexdig[(b >> 0) & 0xF]
            j += 3
    
    return res.decode('ascii') # can raise UnicodeError


quote_from_bytes = quote


def quote_plus(s, safe=''):
    return quote(s, safe, _plus=True)


def _hexval(h):
    if 48 <= h <= 57:  return h - 48
    if 65 <= h <= 70:  return h - 55
    if 97 <= h <= 102: return h - 87
    raise ValueError

def unquote(s, *, _plus=False):
    if s == '':
        return s
    
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
            try:
                n1 = _hexval(bmv[i+0])
                n2 = _hexval(bmv[i+1])
                i += 2
                res[j] = (n1 << 4) | (n2 << 0)
            except (ValueError, IndexError):
                # Invalid or partial %, treat as literal
                res[j] = 37 # percent
        elif b == 43 and _plus:
            # Found '+' and _plus
            res[j] = 32 # space
        else:
            res[j] = b
        
        j += 1
    
    return str(memoryview(res)[:j], 'utf-8') # can raise UnicodeError


def unquote_plus(s):
    return unquote(s, _plus=True)


def urlsplit(url, scheme='', allow_fragments=True):
    if len(url) > 0 and ord(url[0]) <= 32:
        url = url.lstrip()
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


def netlocsplit(netloc): # extension
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


def netlocdict(netloc): # extension
    return dict(zip(('username', 'password', 'hostname', 'port'), netlocsplit(netloc)))


def urlunsplit(components):
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
    if path == '':
        return path
    
    is_abs = path.startswith('/')
    parts = path.split('/')
    stack = []

    # Process
    for p in parts:
        if p == '' or p == '.':
            continue
        if p == '..':
            if stack and stack[-1] != '..':
                stack.pop()
            elif not is_abs:
                stack.append('..')
        else:
            stack.append(p)
    
    # Reconstruct
    if is_abs:
        res = '/' + '/'.join(stack)
    else:
        res = '/'.join(stack)
    del stack
    
    # Trailing slash logic
    if path.endswith('/') and res not in ('', '/'):
        res += '/'
    
    # Empty normalization rules
    if res == '':
        return '.' if not is_abs else '/'
    return res


def urljoin(base, url, allow_fragments=True):
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


def urlencode(query, doseq=False, safe='', quote_via=quote_plus):
    return '&'.join(
        (quote_via(str(key), safe) + '=' + quote_via(str(v), safe))
        for key, val in (query.items() if hasattr(query, 'items') else query)
        for v in (val if doseq else (val,))
    )


def parse_qs(qs, keep_blank_values=False, *, unquote_via=unquote_plus, _qsl=False, _qsd=False):
    if _qsl:
        res = []
    else:
        res = {}
    if not qs:
        return res
    
    i = 0
    n = len(qs)
    
    while (i < n):
        k = qs.find('&', i)
        if k == -1:
            k = n
        j = qs.find('=', i, k)
        
        if j != -1:
            key = unquote_via(qs[i:j])
            val = unquote_via(qs[j+1:k])
            valid = True
        elif keep_blank_values:
            key = unquote_via(qs[i:k])
            val = ''
            valid = True
        else:
            valid = False

        if valid and key:
            if _qsl:
                res.append((key, val))
            elif _qsd:
                res[key] = val
            elif key in res:
                res[key].append(val)
            else:
                res[key] = [val]
        
        i = k + 1
    
    return res


def parse_qsl(*args, **kwargs):
    return parse_qs(*args, **kwargs, _qsl=True)


def urldecode(*args, **kwargs):
    return parse_qs(*args, **kwargs, _qsd=True)

