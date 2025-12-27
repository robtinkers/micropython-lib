# urllib/parse.py

import micropython

__all__ = [
    "quote", "quote_plus", "quote_from_bytes",
    "unquote", "unquote_plus", "unquote_to_bytes",
    "urlsplit_tuple", "locsplit_tuple",
    "urlsplit", "urlunsplit", "urljoin",
    "urlencode", "parse_qs", "parse_qsl", "urldecode", 
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
_QUOTE_TABLE = (
    b'0123456789ABCDEF' 
    b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'
    b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff-.\xff'
    b'0123456789\xff\xff\xff\xff\xff\xff'
    b'\xffABCDEFGHIJKLMNO'
    b'PQRSTUVWXYZ\xff\xff\xff\xff_'
    b'\xffabcdefghijklmno'
    b'pqrstuvwxyz\xff\xff\xff~\xff'
)

@micropython.viper
def _quote_reslen(src: ptr8, srclen: int, qtab: ptr8) -> int:
    reslen = 0
    qfound = False
    i = 0
    while i < srclen:
        b = src[i]
        i += 1
        
        if (32 <= b <= 127) and qtab[b] != 255:
            reslen += 1
            if qtab[b] != b:
                qfound = True
        else:
            reslen += 3
            qfound = True
    
    if qfound:
        return reslen
    else:
        return -1

@micropython.viper
def _quote_process(src: ptr8, srclen: int, qtab: ptr8, dst: ptr8):
    j = 0
    i = 0
    while i < srclen:
        b = src[i]
        i += 1
        
        if (32 <= b <= 127) and qtab[b] != 255:
            dst[j] = qtab[b]
            j += 1
        else:
            dst[j+0] = 37 # '%'
            dst[j+1] = qtab[(b >> 4) & 0xF]
            dst[j+2] = qtab[b & 0xF]
            j += 3

def _quote(s, safe='', *, plus=False, to_bytes=False):
    # can raise UnicodeError
    
    if not s: # empty input
        if to_bytes: return b''
        else: return ''
    
    qtab = bytearray(_QUOTE_TABLE)
    if isinstance(safe, str):
        for c in safe:
            b = ord(c)
            if 32 <= b <= 127: qtab[b] = b
    else:
        for b in safe:
            if 32 <= b <= 127: qtab[b] = b
    if plus:
        qtab[32] = 43 # '+'
    qtab = memoryview(qtab)
    
    if isinstance(s, memoryview):
        src = s
    else:
        src = memoryview(s) # In micropython, memoryview(str) returns read-only UTF-8 bytes
    srclen = len(src)
    
    reslen = _quote_reslen(src, srclen, qtab)
    
    if reslen >= 0:
        res = bytearray(reslen)
        _quote_process(src, srclen, qtab, res)
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
def _unquote_process(src: ptr8, srclen: int, plus: int, res: ptr8) -> int:
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
                b = (n1 << 4) | (n2 << 0)
                i += 2
        
        elif b == 43 and plus: # '+'
            b = 32 # space
        
        res[reslen] = b
        reslen += 1
    
    return reslen

@micropython.viper
def _unquote_required(src: ptr8, srclen: int, plus: int) -> int:
    i = 0
    while i < srclen:
        b = src[i]
        if b == 37 or (plus and b == 43):
            return 1
        i += 1
    return 0

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
    
    plus = 1 if plus else 0
    if _unquote_required(src, srclen, plus):
        res = bytearray(srclen) # Worst Case: result is the same size as the input
        reslen = _unquote_process(src, srclen, plus, res)
        if reslen < srclen:
            res = memoryview(res)[:reslen]
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


def locsplit_tuple(netloc: str) -> tuple: # extension
    if not isinstance(netloc, str):
        raise TypeError('netloc must be a string')
    
    userpass, sep, hostport = netloc.rpartition('@')
    if sep:
        username, sep, password = userpass.partition(':')
        if not sep:
            password = None
    else:
        username, password = None, None
        hostport = userpass
    
    if hostport.startswith('['): # Handle IPv6 (simple check)
        host, sep, port = hostport[1:].partition(']')
        if sep and port.startswith(':'):
            port = port[1:]
    else:
        host, sep, port = hostport.rpartition(':')
        if not sep:
            host, port = port, ''
    
    if host:
        host = host.lower()
    else:
        host = None
    
    if port:
        # Incompatibility:
        # CPython raises ValueError for bad ports
        # we return bad ports as the string
        try:
            port_number = int(port, 10)
        except ValueError:
            pass
        else:
            if (0 <= port_number <= 65535):
                port = port_number
    else:
        port = None
    
    return (username, password, host, port)


def urlsplit_tuple(url: str, scheme='', allow_fragments=True) -> tuple:
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


class SplitResult:
    
    __slots__ = ('scheme', 'netloc', 'path', 'query', 'fragment',
                 'username', 'password', 'hostname', 'port', '_url')
    
    def __init__(self, url: str, scheme='', allow_fragments=True):
        self.scheme, self.netloc, self.path, self.query, self.fragment = urlsplit_tuple(url, scheme, allow_fragments)
        self.username, self.password, self.hostname, self.port = locsplit_tuple(self.netloc)
        self._url = url
    
    def __len__(self):
        return 5
    
    def __iter__(self):
        yield self.scheme
        yield self.netloc
        yield self.path
        yield self.query
        yield self.fragment
    
    def __getitem__(self, i):
        return (self.scheme, self.netloc, self.path, self.query, self.fragment)[i]
    
    def __repr__(self):
        return ('SplitResult(%s)' % repr(self._url))
    
    def geturl(self):
#        return urlunsplit((self.scheme, self.netloc, self.path, self.query, self.fragment)) # match CPython
        return self._url


def urlsplit(url: str, scheme='', allow_fragments=True) -> SplitResult:
    return SplitResult(url, scheme, allow_fragments)


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


# copied from CPython with minor edits
def urljoin(base: str, url: str, allow_fragments=True):
    if not base:
        return url
    if not url:
        return base
    
    bscheme, bnetloc, bpath, bquery, bfragment = urlsplit_tuple(base, None, allow_fragments)
    scheme, netloc, path, query, fragment = urlsplit_tuple(url, None, allow_fragments)
    
    if scheme is None:
        scheme = bscheme
    if scheme != bscheme or (scheme and scheme not in _USES_RELATIVE):
        return url
    if not scheme or scheme in _USES_NETLOC:
        if netloc:
            return urlunsplit(scheme, netloc, path, query, fragment)
        netloc = bnetloc
    
    if not path:
        path = bpath
        if query is None:
            query = bquery
            if fragment is None:
                fragment = bfragment
        return urlunsplit(scheme, netloc, path, query, fragment)
    
    base_parts = bpath.split('/')
    if base_parts[-1] != '':
        # the last item is not a directory, so will not be taken into account
        # in resolving the relative path
        del base_parts[-1]
    
    # for rfc3986, ignore all base path should the first character be root.
    if path[:1] == '/':
        segments = path.split('/')
    else:
        segments = base_parts + path.split('/')
        # filter out elements that would cause redundant slashes on re-joining
        # the resolved_path
        segments[1:-1] = filter(None, segments[1:-1])
    
    resolved_path = []
    
    for seg in segments:
        if seg == '..':
            if resolved_path:
                resolved_path.pop()
        elif seg != '.':
            resolved_path.append(seg)
    
    if segments[-1] == '.' or segments[-1] == '..':
        # do some post-processing here. if the last segment was a relative dir,
        # then we need to append the trailing '/'
        resolved_path.append('')
    
    return urlunsplit(scheme, netloc, '/'.join(resolved_path) or '/', query, fragment)


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

