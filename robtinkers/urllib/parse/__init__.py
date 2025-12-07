# robtinkers/urllib.parse

__all__ = [
    "quote", "quote_plus", "quote_from_bytes",
    "unquote", "unquote_plus", "unquote_to_bytes",
    "netlocsplit", "netlocdict", "urlsplit", "urlunsplit", "urljoin",
    "urlencode", "parse_qs", "parse_qsl", "urldecode", 
]

_USES_NETLOC = frozenset(['file', 'ftp', 'http', 'https', 'ws', 'wss'])

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
def _quote_reslen(qtab: ptr8, src: ptr8, srclen: int) -> int:
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
def _quote_process(qtab: ptr8, src: ptr8, srclen: int, dst: ptr8):
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

def quote(s, safe='/', *, to_bytes=False, _plus=False) -> str:
    # can raise UnicodeError
    
    if not s: # empty input
        if to_bytes:
            return bytes(s)
        elif isinstance(s, str):
            return s
        else:
            return str(s, 'ascii')
    
    qtab = bytearray(_QUOTE_TABLE)
    if isinstance(safe, str):
        for c in safe:
            b = ord(c)
            if 32 <= b <= 127: qtab[b] = b
    else:
        for b in safe:
            if 32 <= b <= 127: qtab[b] = b
    if _plus:
        qtab[32] = 43 # '+'
    qtab = memoryview(qtab)
    
    src = memoryview(s)
    srclen = len(src)
    
    reslen = _quote_reslen(qtab, src, srclen)
    
    if reslen == -1:
        if to_bytes:
            return bytes(s)
        elif isinstance(s, str):
            return s
        else:
            return str(s, 'ascii')
    
    res = bytearray(reslen)
    _quote_process(qtab, src, srclen, res)
    
    if to_bytes:
        return bytes(res)
    else:
        return str(res, 'ascii')


quote_from_bytes = quote


def quote_plus(s, safe='') -> str:
    return quote(s, safe=safe, _plus=True)


@micropython.viper
def _unquote_process(plus: bool, src: ptr8, srclen: int, res: ptr8) -> int:
    qfound = False
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
                qfound = True
                b = (n1 << 4) | (n2 << 0)
                i += 2
        
        elif b == 43 and plus: # '+'
            qfound = True
            b = 32 # space
        
        res[reslen] = b
        reslen += 1
    
    return reslen if qfound else -1


def unquote(s, *, to_bytes=False, _plus=False) -> str:
    # can raise UnicodeError
    
    if not s: # empty input
        if to_bytes:
            return bytes(s)
        elif isinstance(s, str):
            return s
        else:
            return str(s, 'utf-8')
    
    src = memoryview(s) # In micropython, memoryview(str) returns read-only UTF-8 bytes
    srclen = len(src)
    res = bytearray(srclen) # Worst Case: result is the same size as the input
    
    reslen = _unquote_process(_plus, src, srclen, res)
    
    if reslen == -1: # no quotes found
        if to_bytes:
            return bytes(s)
        elif isinstance(s, str):
            return s
        else:
            return str(s, 'utf-8')
    
    res = bytes(memoryview(res)[:reslen])
    
    if to_bytes:
        return res
    else:
        return str(res, 'utf-8')


def unquote_plus(s) -> str:
    return unquote(s, _plus=True)


def unquote_to_bytes(s) -> bytes:
    return unquote(s, to_bytes=True)


def netlocsplit(netloc: str) -> tuple: # extension
    if not isinstance(netloc, str):
        raise TypeError('netloc must be a string')
    
    userpass, sep, hostport = netloc.partition('@')
    if sep:
        username, sep, password = userpass.partition(':')
        if not sep:
            password = None
    else:
        username, password = None, None
        hostport = userpass
    
    if ']' in hostport: # Handle IPv6 (simple check)
        host, sep, port = hostport.rpartition(':')
        if ']' not in host: # The colon was inside the brackets!
            host = hostport
            port = None
    else:
        host, sep, port = hostport.rpartition(':')
        if host:
            host = host.lower()
    
    if not host:
        host = None
    
    try:
        port = int(port, 10)
        if port < 0:
            port = None
    except ValueError:
        port = None
    
    return (username, password, host, port)


def netlocdict(netloc: str) -> dict: # extension
    return dict(zip(('username', 'password', 'hostname', 'port'), netlocsplit(netloc)))


def _urlsplit(url: str, scheme='', allow_fragments=True) -> tuple:
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


def urlsplit(url: str, *args, **kwargs) -> tuple:
    return _urlsplit(url, *args, **kwargs)


#from collections import namedtuple
#_SplitTuple = namedtuple('_SplitTuple', ('scheme', 'netloc', 'path', 'query', 'fragment'))
#class SplitResult(_SplitTuple):
#    @property
#    def username(self):
#        return netlocsplit(self.netloc)[0]
#    @property
#    def password(self):
#        return netlocsplit(self.netloc)[1]
#    @property
#    def hostname(self):
#        return netlocsplit(self.netloc)[2]
#    @property
#    def port(self):
#        return netlocsplit(self.netloc)[3]
#def urlsplit(url: str, *args, **kwargs) -> SplitResult:
#    return SplitResult(*_urlsplit(url, *args, **kwargs))


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


def urljoin(base: str, url: str, allow_fragments=True) -> str:
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

