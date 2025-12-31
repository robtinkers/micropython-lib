# urllib/parse.py

import micropython
from array import array
from uctypes import addressof

__all__ = [
    "quote", "quote_plus", "quote_from_bytes",
    "unquote", "unquote_plus", "unquote_to_bytes",
    "urlencode", "parse_qs", "parse_qsl", "urldecode", 
    "urlsplit", "urlunsplit", "urljoin",
]

_USES_RELATIVE = frozenset([
    'file', 'ftp', 'http', 'https', 'rtsp', 'rtsps', 'sftp', 'ws', 'wss',
])

_USES_NETLOC = frozenset([
    'file', 'ftp', 'http', 'https', 'rtsp', 'rtsps', 'sftp', 'ws', 'wss',
])

_HEX_DIGITS = b'0123456789ABCDEF'

# Standard masks for ASCII 32-127
# 0-31:   not used
# 32-63:  0-9, -, .
# 64-95:  A-Z, _
# 96-127: a-z, ~
_MASKS_BASE = (0, 0x03FF6000, 0x87FFFFFE, 0x47FFFFFE)

_MASKS_QUOTE = array('I', [
    0,
    _MASKS_BASE[1] | (1 << 15), # /
    _MASKS_BASE[2], 
    _MASKS_BASE[3]
])

_MASKS_QUOTE_PLUS = array('I', [
    1, # plus mode
    _MASKS_BASE[1], 
    _MASKS_BASE[2], 
    _MASKS_BASE[3]
])

@micropython.viper
def _quote_helper(src: ptr8, srclen: int, masks: ptr32, res: ptr8) -> int:
    write = int(res) != 0
    modified = 0
    reslen = 0
    b = 0
    
    # Unpack masks into local variables for speed
    flags = masks[0]
    mask1 = masks[1] # 32-63
    mask2 = masks[2] # 64-95
    mask3 = masks[3] # 96-127
    
    hex_digits = ptr8(addressof(_HEX_DIGITS))
    
    i = 0
    while i < srclen:
        b = src[i]
        i += 1
        
        if b == 32 and flags == 1: # space and quote_plus
            modified = 1
            if write: res[reslen] = 43 # '+'
            reslen += 1
            continue
        
        if b < 32:
            is_safe = 0
        elif b < 64:
            is_safe = (mask1 >> (b & 31)) & 1
        elif b < 96:
            is_safe = (mask2 >> (b & 31)) & 1
        elif b < 128:
            is_safe = (mask3 >> (b & 31)) & 1
        else:
            is_safe = 0
        
        if is_safe:
            if write: res[reslen] = b
            reslen += 1
        else:
            modified = 1
            if write:
                res[reslen] = 37 # '%'
                res[reslen + 1] = hex_digits[b >> 4]
                res[reslen + 2] = hex_digits[b & 0xF]
            reslen += 3
    
    return reslen if modified else 0

def _quote(s, safe, flags):
    if isinstance(s, (memoryview, bytes, bytearray)):
        src = s
    else:
        src = memoryview(s)
    
    srclen = len(src)
    if srclen == 0:
        return ''
    
    # Fast path for standard methods with default arguments
    if flags == 0 and safe == '/': # quote('foo')
        masks = addressof(_MASKS_QUOTE)
    elif flags == 1 and safe == '': # quote_plus('bar')
        masks = addressof(_MASKS_QUOTE_PLUS)
    else:
        # Slow path: build custom masks
        masks_custom = array('I', [flags, _MASKS_BASE[1], _MASKS_BASE[2], _MASKS_BASE[3]])
        for c in safe:
            if isinstance(c, str):
                c = ord(c)
            if 32 <= c <= 127:
                masks_custom[(c >> 5)] |= (1 << (c & 31))
        masks = addressof(masks_custom)
    
    reslen = _quote_helper(src, srclen, masks, 0)
    if reslen <= 0:
        if isinstance(s, str):
            return s
        elif isinstance(s, (bytes, bytearray)):
            return s.decode('ascii')
        else:
            return bytes(s).decode('ascii')
    
    res = bytearray(reslen)
    _quote_helper(src, srclen, masks, res)
    return res.decode('ascii')

def quote(string, safe='/', encoding=None, errors=None): # encoding and errors are unused
    return _quote(string, safe, 0)

def quote_plus(string, safe='', encoding=None, errors=None): # encoding and errors are unused
    return _quote(string, safe, 1)

def quote_from_bytes(string, safe='/'):
    return _quote(string, safe, 0)



#_HEX_TO_INT = const(b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\xff\xff\xff\xff\xff\xff\xff\x0a\x0b\x0c\x0d\x0e\x0f\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x0a\x0b\x0c\x0d\x0e\x0f\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff')

@micropython.viper
def _unquote_helper(src: ptr8, srclen: int, flags: int, res: ptr8) -> int:
    write = int(res) != 0
    modified = 0
    reslen = 0
    n1 = n2 = b = 0
    
#    hex_to_int = ptr8(addressof(_HEX_TO_INT))
    
    i = 0
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
#                n1 = hex_to_int[n1]
                
                n2 = src[i+1]
                if   48 <= n2 <= 57: n2 -= 48
                elif 65 <= n2 <= 70: n2 -= 55
                elif 97 <= n2 <=102: n2 -= 87
                else: n2 = 255
#                n2 = hex_to_int[n2]
            else:
                n1 = 255
                n2 = 255
            
            if n1 != 255 and n2 != 255:
                modified = 1
                b = (n1 << 4) | (n2 << 0)
                i += 2
        
        elif b == 43 and flags == 1: # '+'
            modified = 1
            b = 32 # space
        
        if write:
            res[reslen] = b
        reslen += 1
    
    return reslen if modified else 0

def _unquote(s, start, end, flags) -> bytes:
    if isinstance(s, (memoryview, bytes, bytearray)):
        src = s
    else:
        # if s is a string, then start and end should be 0 and None
        # otherwise you're going to have a very bad time
        src = memoryview(s)
    
    srclen = len(src)
    if srclen == 0:
        return b''
    
    noslice = (start == 0 and end is None)
    if end is None or end > srclen:
        end = srclen
    if start < 0:
        start = 0
    if start >= end:
        return b''
    
    adr = addressof(src)
    reslen = _unquote_helper(adr + start, end - start, flags, 0)
    if reslen <= 0:
        if isinstance(s, str):
            res = s.encode('utf-8')
        elif isinstance(s, bytes):
            res = s
        elif not noslice and isinstance(s, (bytearray, memoryview)):
            # slight peak memory saving over the default code path
            return bytes(s[start:end])
        else:
            res = bytes(s)
        if noslice:
            return res
        else:
            return res[start:end]
    
    res = bytearray(reslen)
    _unquote_helper(adr + start, end - start, flags, res)
    return bytes(res)

def unquote(s, encoding='utf-8', errors='replace'): # errors is unused
    return _unquote(s, 0, None, 0).decode(encoding)

def unquote_plus(s, encoding='utf-8', errors='replace'): # errors is unused
    return _unquote(s, 0, None, 1).decode(encoding)

def unquote_to_bytes(s) -> bytes:
    return _unquote(s, 0, None, 0)



def _urlencode_generator(query, doseq=False, safe='', encoding=None, errors=None, quote_via=quote_plus):
    if hasattr(query, 'items') and callable(query.items):
        query = query.items()
    for key, val in query:
        if not isinstance(key, (str, bytes, bytearray, memoryview)):
            key = str(key)
        key = quote_via(key, safe, encoding, errors)
        if isinstance(val, (str, bytes, bytearray, memoryview)):
            yield key + '=' + quote_via(val, safe, encoding, errors)
        elif doseq:
            for v in val:
                if not isinstance(v, (str, bytes, bytearray, memoryview)):
                    v = str(v)
                yield key + '=' + quote_via(v, safe, encoding, errors)
        else:
            yield key + '=' + quote_via(str(val), safe, encoding, errors)

def urlencode(query, *args, **kwargs) -> str:
    return '&'.join(_urlencode_generator(query, *args, **kwargs))



@micropython.viper
def _mv_find(mv: ptr8, b: int, start: int, end: int) -> int:
    i = start
    while i < end:
        if mv[i] == b:
            return i
        i += 1
    return -1

def _parse_generator(qs, keep_blank_values=False, strict_parsing=False,
                     encoding='utf-8', errors='replace',
                     max_num_fields=None, separator='&'):
    if not isinstance(qs, (memoryview, bytes, bytearray)):
        qs = memoryview(qs)
    n = len(qs)
    if n == 0:
        return
    
    sep = ord(separator)
    i = 0
    num_fields = 0
    
    while i <= n:
        num_fields += 1
        if max_num_fields is not None and num_fields > max_num_fields:
            raise ValueError('max_num_fields exceeded')
        
        j = _mv_find(qs, sep, i, n)
        if j < 0:
            j = n
        eq = _mv_find(qs, 61, i, j) # '='
        
        try:
            if eq >= 0:
                # key=value
                if keep_blank_values or (eq + 1 < j):
                    key = _unquote(qs, i, eq, True).decode(encoding)
                    val = _unquote(qs, eq + 1, j, True).decode(encoding)
                    yield key, val
            else:
                # key (no '=')
                if strict_parsing:
                    raise ValueError('bad query field')
                if keep_blank_values:
                    key = _unquote(qs, i, j, True).decode(encoding)
                    yield key, ''
        except UnicodeError:
            if errors == 'strict':
                raise
        
        if j == n:
            break
        i = j + 1

def parse_qs(qs, *args, **kwargs) -> dict:
    res = {}
    for key, val in _parse_generator(qs, *args, **kwargs):
        if key in res:
            res[key].append(val)
        else:
            res[key] = [val]
    return res

def parse_qsl(qs, *args, **kwargs) -> list:
    return list(_parse_generator(qs, *args, **kwargs))

def urldecode(qs, *args, **kwargs) -> dict:
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
    
    if hostport[0] == '[': # Handle IPv6 (simple check)
        if (sep := hostport.find(']')) >= 0:
            host, port_string = hostport[1:sep], hostport[sep+1:]
        else: # *shrug*
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
    
    return (username, password, host, port_string or None)

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

class SplitResult(tuple):
    
    def __init__(self, scheme, netloc, path, query, fragment):
        super().__init__((scheme, netloc or '', path or '', query or '', fragment or ''))
        self.username, self.password, self.hostname, self._port = _locsplit(self[1])
    
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
        if self._port is None:
            return None
        if not self._port or self._port[0] != ':':
            raise ValueError('bad port number')
        try:
            port = int(self._port[1:], 10)
        except ValueError:
            raise ValueError('bad port number')
        else:
            if not (0 <= port <= 65535):
                raise ValueError('bad port number')
        return port
    
    def geturl(self):
        return urlunsplit(self)

def urlsplit(url: str, scheme='', allow_fragments=True) -> SplitResult:
    return SplitResult(*_urlsplit(url, scheme, allow_fragments))



# derived from CPython (all bugs are mine)
def _urlunsplit(scheme, netloc, url, query, fragment) -> str:
    # assert url is not None
    if netloc is not None:
        if url[0] != '/':
            url = '/' + url
        url = '//' + netloc + url
    elif url.startswith('//'):
        url = '//' + url
    if scheme:
        url = scheme + ':' + url
    if query is not None:
        url += '?' + query
    if fragment is not None:
        url += '#' + fragment
    return url

def urlunsplit(components: tuple) -> str:
    scheme, netloc, url, query, fragment = components
    if netloc == '':
        if not scheme or scheme not in _USES_NETLOC or (url and url[0] != '/'):
            netloc = None
    return _urlunsplit(scheme, netloc, url or '', query, fragment)



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
    if path[0] == '/': # 'not path' was already checked earlier
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

