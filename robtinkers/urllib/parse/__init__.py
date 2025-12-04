# robtinkers/urllib.parse

__all__ = [
    "quote", "quote_plus", "unquote", "unquote_plus",
    "urlsplit", "netlocsplit", "netlocdict", "urlunsplit", "urljoin",
    "urlencode", "parse_qs", "parse_qsl", "urldecode", 
]

import io


_hexdigits = b'0123456789ABCDEF'
_safe_set = frozenset([45, 46, 95, 126]) # -._~
_safe_set_with_slash = frozenset([45, 46, 95, 126, 47]) # -._~/

def quote(s, safe='/', *, _plus=False):
    if s == '':
        return s
    
    bmv = memoryview(s) # In micropython, memoryview(str) returns read-only UTF-8 bytes
    
    if safe == '/':
        safe_ords = _safe_set_with_slash
    elif safe == '':
        safe_ords = _safe_set
    elif isinstance(safe, (set, frozenset)): # extension (must be a set of ord values)
        safe_ords = safe
    else:
        safe_ords = set(_safe_set) # creates a writeable copy
        safe_ords.update(set(ord(c) for c in safe)) # safe characters must be ASCII
    
    fast = True
    for b in bmv:
        if (48 <= b <= 57) or (65 <= b <= 90) or (97 <= b <= 122) or (b in safe_ords):
            continue
        fast = False
        break
    if fast:
        return s
    
    res = io.BytesIO()
    
    # Pre-allocate tiny buffers to avoid creating bytes objects inside the loop
    tmp1 = bytearray(1)
    tmp1mv = memoryview(tmp1)
    tmp3 = bytearray(b'%00')
    tmp3mv = memoryview(tmp3)
    
    for b in bmv:
        if (48 <= b <= 57) or (65 <= b <= 90) or (97 <= b <= 122) or (b in safe_ords):
            tmp1mv[0] = b
            res.write(tmp1)
        elif b == 32 and _plus:
            tmp1mv[0] = 43 # +
            res.write(tmp1)
        else:
            tmp3mv[1] = _hexdigits[b >> 4]
            tmp3mv[2] = _hexdigits[b & 0xf]
            res.write(tmp3)
    
    return res.getvalue().decode('utf-8') # can raise UnicodeError


def quote_plus(s, safe=''):
    return quote(s, safe, _plus=True)


def unquote(s, *, _plus=False):
    if s == '':
        return ''
    
    bmv = memoryview(s) # In micropython, memoryview(str) returns read-only UTF-8 bytes
    
    res = io.BytesIO()
    
    # Pre-allocate tiny buffers to avoid creating bytes objects inside the loop
    tmp1 = bytearray(1)
    tmp1mv = memoryview(tmp1)
    
    i = 0
    n = len(bmv)
    start = 0
    
    while (i < n):
        byte = bmv[i]
        if (byte != 37) and (byte != 43 or not _plus):
            i += 1
            continue
        # Found '%' or '+' (if _plus)
        
        # Write pending data
        if start < i:
            res.write(bmv[start:i])
        
        # Found '+' (if _plus)
        if byte == 43 and _plus: # +
            res.write(b' ')
            i += 1
            start = i
            continue
        
        # We must have found '%'
        if i + 2 < n:
            try:
                # Manual hex conversion to avoid slicing allocation
                digit1 = bmv[i+1]
                digit2 = bmv[i+2]
                
                # Convert ASCII hex char to int
                if 48 <= digit1 <= 57: d1 = digit1 - 48
                elif 65 <= digit1 <= 70: d1 = digit1 - 55
                elif 97 <= digit1 <= 102: d1 = digit1 - 87
                else: raise ValueError
                
                if 48 <= digit2 <= 57: d2 = digit2 - 48
                elif 65 <= digit2 <= 70: d2 = digit2 - 55
                elif 97 <= digit2 <= 102: d2 = digit2 - 87
                else: raise ValueError
                
                tmp1mv[0] = (d1 << 4) | d2
                res.write(tmp1)
                i += 3
                start = i
                continue
            except ValueError:
                pass
        
        # Invalid hex or incomplete, keep the % literal and advance by 1
        res.write(b'%')
        i += 1
        start = i
    
    # Write remainder
    if start < n:
        res.write(bmv[start:])
    
    return res.getvalue().decode('utf-8') # can raise UnicodeError


def unquote_plus(s):
    return unquote(s, _plus=True)


def urlsplit(url, scheme='', allow_fragments=True):
    netloc = query = fragment = ''
    if allow_fragments:
        url, _, fragment = url.partition('#')
    url, _, query = url.partition('?')
    
    if url.startswith('//'):
        url = url[2:]
        netloc, _, path = url.partition('/')
        if path:
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
                netloc, _, path = url.partition('/')
                if path:
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
    if not path:
        return path
    
    is_absolute = path.startswith('/')
    
    stack = []
    for seg in path.split('/'):
        if seg == '..':
            if stack and stack[-1] != '..':
                stack.pop()
            elif not is_absolute:
                stack.append(seg)
        elif seg != '.' and seg != '':
            stack.append(seg)
    
    res = '/'.join(stack)
    if is_absolute:
        res = '/' + res
    
    if path.endswith(('/', '/.', '/..')) or path in ('.', '..'):
        if not res.endswith('/'):
            res += '/'
    
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
    elif (i := bp.rfind('/')) != -1:
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
        result = []
    else:
        result = {}
    if not qs:
        return result
    
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
        elif keep_blank_values:
            key = unquote_via(qs[i:k])
            val = ''
        else:
            i = k + 1
            continue
        i = k + 1
        
        if _qsl:
            result.append((key, val))
        elif _qsd:
            result[key] = val
        elif key in result:
            result[key].append(val)
        else:
            result[key] = [val]
    
    return result


def parse_qsl(*args, **kwargs):
    return parse_qs(*args, **kwargs, _qsl=True)


def urldecode(*args, **kwargs):
    return parse_qs(*args, **kwargs, _qsd=True)

