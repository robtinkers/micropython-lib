# urllib/parse.py

import micropython

__all__ = [
    "quote", "quote_plus", "quote_from_bytes",
    "unquote", "unquote_plus", "unquote_to_bytes",
    "urlencode", "parse_qs", "parse_qsl", "urldecode", 
    "urlsplit", "urlunsplit", "urljoin",
]

_USES_RELATIVE = frozenset([
    '', 'file', 'ftp', 'http', 'https', 'rtsp', 'rtsps', 'sftp', 'ws', 'wss',
])

_USES_NETLOC = frozenset([
    '', 'file', 'ftp', 'http', 'https', 'rtsp', 'rtsps', 'sftp', 'ws', 'wss',
])

# Table Size: 128 Bytes
# Indices 0-15:   Hex Digits '0'-'F' (used for lookup during encoding)
# Indices 16-31:  Unused/Unsafe (0xFF)
# Indices 32-127: Mapping (0xFF = Encode, Other = Output Char)
_QUOTE_PLUS = (
    b'0123456789ABCDEF' 
    b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'
    b'+\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff-.\xff'
    b'0123456789\xff\xff\xff\xff\xff\xff'
    b'\xffABCDEFGHIJKLMNO'
    b'PQRSTUVWXYZ\xff\xff\xff\xff_'
    b'\xffabcdefghijklmno'
    b'pqrstuvwxyz\xff\xff\xff~\xff'
)

@micropython.viper
def _quote_helper(src: ptr8, srclen: int, qtab: ptr8, res: ptr8) -> int:
    modified = 0
    reslen = 0
    i = 0
    while i < srclen:
        b = src[i]
        i += 1
        
        if (32 <= b <= 127) and qtab[b] != 255:
            if qtab[b] != b:
                modified = 1
            if int(res):
                res[reslen] = qtab[b]
            reslen += 1
        else:
            modified = 1
            if int(res):
                res[reslen+0] = 37 # '%'
                res[reslen+1] = qtab[(b >> 4) & 0xF]
                res[reslen+2] = qtab[b & 0xF]
            reslen += 3
    
    return reslen if modified else 0

def _quote(s, safe='', *, plus=False, to_bytes=False):
    # can raise UnicodeError
    
    if not s: # empty input
        if to_bytes: return b''
        else: return ''
    
    if safe == '' and plus:
        # we optimise for quote_plus() with safe='' (the default)
        qtab = _QUOTE_PLUS
    else:
        # other methods/arguments will have a slight memory churn
        qtab = bytearray(_QUOTE_PLUS)
        if isinstance(safe, str):
            for c in safe:
                b = ord(c)
                if 32 <= b <= 127: qtab[b] = b
        else:
            for b in safe:
                if 32 <= b <= 127: qtab[b] = b
        if not plus:
            qtab[32] = 0xFF
    qtab = memoryview(qtab)
    
    if isinstance(s, memoryview):
        src = s
    else:
        src = memoryview(s) # In micropython, memoryview(str) returns read-only UTF-8 bytes
    srclen = len(src)
    
    reslen = _quote_helper(src, srclen, qtab, 0)
    if reslen > 0:
        res = bytearray(reslen)
        _quote_helper(src, srclen, qtab, res)
    else:
        res = s
    
    if to_bytes:
        if isinstance(res, str): return res.encode()
        elif isinstance(res, bytes): return res
        elif isinstance(res, (bytearray, memoryview)): return bytes(res)
        else: return bytes(res)
    elif isinstance(res, str): return res
    elif isinstance(res, (bytes, bytearray)): return res.decode('ascii')
    elif isinstance(res, memoryview): return bytes(res).decode('ascii')
    else: return str(res)

def quote(s, safe='/') -> str:
    return _quote(s, safe=safe)

def quote_plus(s, safe='') -> str:
    return _quote(s, safe=safe, plus=True)

quote_from_bytes = quote



@micropython.viper
def _unquote_helper(src: ptr8, srclen: int, plus: int, res: ptr8) -> int:
    modified = 0
    reslen = 0
    n1 = n2 = b = i = 0
    while (i < srclen):
        b = src[i]
        i += 1
        
        if b == 37: # '%'
            if (i + 1 < srclen):
                n1 = src[i+0]
                if   48 <= n1 <= 57: n1 -= 48
                elif 65 <= n1 <= 70: n1 -= 55
                elif 97 <= n1 <=102: n1 -= 87
                else: n1 = 255
                
                n2 = src[i+1]
                if   48 <= n2 <= 57: n2 -= 48
                elif 65 <= n2 <= 70: n2 -= 55
                elif 97 <= n2 <=102: n2 -= 87
                else: n2 = 255
            else:
                n1 = 255
                n2 = 255
            
            if n1 != 255 and n2 != 255:
                modified = 1
                b = (n1 << 4) | (n2 << 0)
                i += 2
        
        elif b == 43 and plus: # '+'
            modified = 1
            b = 32 # space
        
        if int(res):
            res[reslen] = b
        reslen += 1
    
    return reslen if modified else 0

def _unquote(s, *, plus=False, to_bytes=False):
    # can raise UnicodeError
    
    if not s: # empty input
        if to_bytes: return b''
        else: return ''
    
    if isinstance(s, memoryview):
        src = s
    else:
        src = memoryview(s) # In micropython, memoryview(str) returns read-only UTF-8 bytes
    srclen = len(src)
    
    flag_plus = 1 if plus else 0
    reslen = _unquote_helper(src, srclen, flag_plus, 0)
    if reslen:
        res = bytearray(reslen)
        _unquote_helper(src, srclen, flag_plus, res)
    else:
        res = s
    
    if to_bytes:
        if isinstance(res, str): return res.encode()
        elif isinstance(res, bytes): return res
        elif isinstance(res, (bytearray, memoryview)): return bytes(res)
        else: return bytes(res)
    elif isinstance(res, str): return res
    elif isinstance(res, (bytes, bytearray)): return res.decode('utf-8')
    elif isinstance(res, memoryview): return bytes(res).decode('utf-8')
    else: return str(res)

def unquote(s) -> str:
    return _unquote(s)

def unquote_plus(s) -> str:
    return _unquote(s, plus=True)

def unquote_to_bytes(s) -> bytes:
    return _unquote(s, to_bytes=True)



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



def _parse_generator(qs: str, keep_blank_values=False, strict_parsing=False, unquote_via=unquote_plus):
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
                raise ValueError("bad query field: %r" % (qs[i:j],))
            if keep_blank_values:
                yield unquote_via(qs[i:j]), ''

def parse_qs(qs: str, *args, **kwargs) -> dict:
    res = {}
    for key, val in _parse_generator(qs, *args, **kwargs):
        if key in res:
            res[key].append(val)
        else:
            res[key] = [val]
    return res

def parse_qsl(qs: str, *args, **kwargs) -> list:
    return list(_parse_generator(qs, *args, **kwargs))

def urldecode(qs: str, *args, **kwargs) -> dict:
    res = {}
    for key, val in _parse_generator(qs, *args, **kwargs):
        res[key] = val
    return res



def _locsplit(netloc: str) -> tuple: # extension
    if (sep := netloc.rfind('@')) >= 0:
        userpass, hostport = netloc[:sep], netloc[sep+1:]
        if (sep := userpass.find(':')) >= 0:
            username, password = userpass[:sep], userpass[sep+1:]
        else:
            username, password = userpass, None
    else:
        hostport = netloc
        username, password = None, None
    
    if hostport.startswith('['): # Handle IPv6 (simple check)
        if (sep := hostport.find(']')) >= 0:
            host, port_string = hostport[1:sep], hostport[sep+1:]
        else:
            host, port_string = hostport, ''
    else:
        if (sep := hostport.rfind(':')) >= 0:
            host, port_string = hostport[:sep], hostport[sep:]
        else:
            host, port_string = hostport, ''
    
    if host:
        host = host.lower()
    else:
        host = None
    
    # Incompatibility:
    # CPython raises ValueError for bad ports
    # we return bad ports as the string
    port = port_string
    if port_string.startswith(':'):
        try:
            port_number = int(port_string[1:], 10)
        except ValueError:
            pass
        else:
            if (0 <= port_number <= 65535):
                port = port_number
    elif port_string == '':
        port = None
    
    return (username, password, host, port)

# derived from CPython (all bugs are mine)
def _urlsplit(url: str, scheme, allow_fragments: bool) -> tuple:
    url = url.lstrip()
    if scheme:
        scheme = scheme.strip()
    
    netloc = query = fragment = None
    if (colon := url.find(':')) > 0 and url[0].isalpha():
        if (slash := url.find('/')) < 0 or colon < slash:
            scheme, url = url[:colon].lower(), url[colon+1:]
    if url.startswith('//'):
        delim = len(url)
        for c in '/?#':
            if 0 <= (x := url.find(c, 2)) < delim:
                delim = x
        netloc, url = url[2:delim], url[delim:]
    
    if allow_fragments and (i := url.find('#')) >= 0:
        url, fragment = url[:i], url[i+1:]
    
    if (i := url.find('?')) >= 0:
        url, query = url[:i], url[i+1:]
    
    return (scheme, netloc, url, query, fragment)

class SplitResult:
    
    __slots__ = ('scheme', 'netloc', 'path', 'query', 'fragment',
                 'username', 'password', 'hostname', 'port', '_url')
    
    def __init__(self, url: str, scheme, allow_fragments: bool):
        self.scheme, netloc, path, query, fragment = _urlsplit(url, scheme, allow_fragments)
        self.netloc = netloc or ''
        self.path = path or ''
        self.query = query or ''
        self.fragment = fragment or ''
        self.username, self.password, self.hostname, self.port = _locsplit(self.netloc)
    
    def __len__(self):
        return 5
    
    def __iter__(self):
        yield self.scheme
        yield self.netloc
        yield self.path
        yield self.query
        yield self.fragment
    
    def __getitem__(self, i):
#        return (self.scheme, self.netloc, self.path, self.query, self.fragment)[i]
        if i == 0: return self.scheme
        if i == 1: return self.netloc
        if i == 2: return self.path
        if i == 3: return self.query
        if i == 4: return self.fragment
        raise IndexError('tuple index out of range')
    
    def geturl(self):
        return urlunsplit(self)

def urlsplit(url: str, scheme='', allow_fragments=True) -> SplitResult:
    return SplitResult(url, scheme, allow_fragments)



# derived from CPython (all bugs are mine)
def _urlunsplit(scheme, netloc, url, query, fragment) -> str:
    if netloc is not None:
        if url and not url.startswith('/'):
            url = '/' + url
        url = '//' + netloc + url
    elif url.startswith('//'):
        url = '//' + url
    if scheme:
        url = scheme + ':' + url
    if query is not None:
        url = url + '?' + query
    if fragment is not None:
        url = url + '#' + fragment
    return url

# derived from CPython (all bugs are mine)
def urlunsplit(components: tuple) -> str:
    scheme, netloc, url, query, fragment = components
    if not netloc:
        if scheme and scheme in _USES_NETLOC and (not url or url.startswith('/')):
            netloc = ''
        else:
            netloc = None
    return _urlunsplit(scheme or None, netloc, url, query or None, fragment or None)



# derived from CPython (all bugs are mine)
def urljoin(base: str, url: str, allow_fragments: bool=True) -> str:
    if not base:
        return url
    if not url:
        return base
    
    bscheme, bnetloc, bpath, bquery, bfragment = _urlsplit(base, None, allow_fragments)
    scheme, netloc, path, query, fragment = _urlsplit(url, None, allow_fragments)
    
    if scheme is None:
        scheme = bscheme
    if scheme != bscheme or (scheme and scheme not in _USES_RELATIVE):
        return url
    if not scheme or scheme in _USES_NETLOC:
        if netloc:
            return urlunsplit((scheme, netloc, path, query, fragment))
        netloc = bnetloc
    
    if not path:
        path = bpath
        if query is None:
            query = bquery
            if fragment is None:
                fragment = bfragment
        return _urlunsplit(scheme, netloc, path, query, fragment)
    
    base_parts = bpath.split('/')
    if base_parts[-1] != '':
        # the last item is not a directory, so will not be taken into account
        # in resolving the relative path
        del base_parts[-1]
    
    # for rfc3986, ignore all base path should the first character be root.
    if path.startswith('/'):
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
        if seg == '..':
            if resolved_path:
                resolved_path.pop()
        elif seg != '.':
            resolved_path.append(seg)
    
    if segments[-1] in ('.', '..'):
        # do some post-processing here. if the last segment was a relative dir,
        # then we need to append the trailing '/'
        resolved_path.append('')
    
    return _urlunsplit(scheme, netloc, '/'.join(resolved_path) or '/', query, fragment)

