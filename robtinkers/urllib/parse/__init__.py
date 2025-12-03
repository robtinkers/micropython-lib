
_QUOTE_PLUS = {
    ord('\t'):'%09',
    ord('\n'):'%0A',
    ord('\r'):'%0D',
    ord('"'): '%22',
    ord('#'): '%23',
    ord('%'): '%25',
    ord('&'): '%26',
    ord("'"): '%27',
    ord('+'): '%2B',
    ord('/'): '%2F',
    ord(';'): '%3B',
    ord('='): '%3D',
    ord('?'): '%3F',
    ord(' '): '+',
}

def quote_plus(s, safe=''):
    # Similar to Cpython but uses a blacklist for efficiency
    # Adapted from micropython-lib string.translate()
    import io

    sb = io.StringIO()
    for c in s:
        v = ord(c)
        if v in _QUOTE_PLUS and c not in _safe:
            v = _QUOTE_PLUS[v]
            if isinstance(v, int):
                sb.write(chr(v))
            elif v is not None:
                sb.write(v)
        else:
            sb.write(c)
    return sb.getvalue()

def quote(s, safe='/'):
    # Similar to Cpython but uses a blacklist for efficiency
    s = quote_plus(s, safe)
    if '+' in s:  # Avoid creating a new object if not necessary
        s = s.replace('+', '%20')
    return s

def unquote(s):
    # Similar to Cpython. Raises ValueError if unable to percent-decode.
    if '%' not in s:
        return s
    parts = s.split('%')
    result = bytearray()
    result.extend(parts[0].encode())
    for item in parts[1:]:
        if len(item) < 2:
            raise ValueError()
        result.append(int(item[:2], 16))
        result.extend(item[2:].encode())
    return result.decode()

def unquote_plus(s):
    # Similar to Cpython
    if '+' in s:  # Avoid creating a new object if not necessary
        s = s.replace('+', ' ')
    return unquote(s)

def urlencode(data):
    # Similar to Cpython
    parts = []
    for key, val in data.items():
        if True:  # emulates quote_via=quote_plus
            key, val = quote_plus(key), quote_plus(val)
        if key:
            parts.append(key + '=' + val)
    return '&'.join(parts)

def urldecode(qs):
    # Similar to CPython but returns a simple dict, not a dict of lists.
    # For example, urldecode('foo=1&bar=2&baz') returns {'foo': '1', 'bar': '2', 'baz': ''}.
    data = {}
    parts = qs.split('&')
    for part in parts:
        key, sep, val = part.partition('=')
        if True:
            key, val = unquote_plus(key), unquote_plus(val)
        if key:
            data[key] = val
    return data


# robtinkers/urllib_parse.py


def urlsplit(url, scheme=''):
    """Poor man's urllib.parse.urlsplit()"""
    url, _, fragment = url.partition('#')
    url, _, query = url.partition('?')
    if url.startswith('//'):
        url = url[2:]
    elif url.startswith('/'):
        return scheme, '', url, query, fragment
    else:
        colon = url.find(':')
        slash = url.find('/')
        if colon >= 0 and (slash == -1 or slash > colon) and colon + 3 <= len(url) and url[colon:colon+3] == '://':
            # we only support URLs with '://' format
            if colon > 0:
                scheme = url[:colon].lower()
            url = url[colon+3:]
        else:
            return scheme, '', url, query, fragment
    netloc, slash, path = url.partition('/')
    return scheme, netloc, slash + path, query, fragment


def netlocsplit(netloc):
    """Poor man's urllib.parse.urlsplit() part 2"""
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
        else: # malformed
            hostname = hostport[1:]
            port = None
    else:
        # IPv4 or hostname
        hostname, sep, port = hostport.rpartition(':')
        if not sep:
            hostname, port = hostport, None
    
    try:
        port = int(port, 10)
        if not (0 <= port <= 65535):
            port = None
    except (TypeError, ValueError):
        port = None
    
    return (username, password, hostname, port)  # port is int or None


def _normalize_path(path):
    segments = path.split('/')
    normalized = []
    for seg in segments:
        if seg == '..':
            if normalized and normalized[-1] != '':
                normalized.pop()
        elif seg != '.' and seg != '':
            normalized.append(seg)
    if path.startswith('/'):
        return '/' + '/'.join(normalized)
    else:
        return '/'.join(normalized)


def urljoin(base, url, allow_fragments=True):
    """Poor man's urllib.parse.urljoin()"""

    if not allow_fragments:
        url = url.split('#', 1)[0]
    
    # Check for absolute url
    uscheme, unetloc, upath, uquery, ufragment = urlsplit(url)
    if uscheme:
        return url
    
    # Parse the base URL into its components.
    bscheme, bnetloc, bpath, _, _ = urlsplit(base)
    
    # Handle scheme-relative URLs
    if url.startswith('//'):
        return bscheme + (':' if bscheme else '') + url
    
    # Handle absolute paths
    if url.startswith('/'):
        joined = bscheme + ('://' if bscheme else '') + bnetloc + _normalize_path(upath)
    else:
        # Handle relative paths
        if not bpath.endswith('/'):
            bpath = bpath.rsplit('/', 1)[0] + '/'
        joined = bscheme + ('://' if bscheme else '') + bnetloc + _normalize_path(bpath + upath)
    
    if uquery:
        joined += '?' + uquery
    if ufragment:  # will be empty if not allow_fragments 
        joined += '#' + ufragment
    return joined


def parse_qs(qs, *, keep_blank_values=False, _qsd=False, _qsl=False):
    """Poor man's urllib.parse.parse_qs() and .parse_qsl()"""
    if _qsd or not _qsl:
        result = {}
    else:
        result = []
    for ksv in qs.split('&'):
        if not ksv:
            continue
        key, sep, val = ksv.partition('=')
        if not sep and not keep_blank_values:
            continue
        key = unquote_plus(key)
        val = unquote_plus(val)
        if _qsd:
            result[key] = val
        elif _qsl:
            result.append((key, val))
        elif key in result:
            result[key].append(val)
        else:
            result[key] = [val]
    return result


def parse_qsd(qs, *, keep_blank_values=False):
    """A simplified version of parse_qs with just the last value seen."""
    return parse_qs(qs, keep_blank_values=keep_blank_values, _qsd=True)


def parse_qsl(qs, *, keep_blank_values=False):
    """Poor man's urllib.parse.parse_qsl()"""
    return parse_qs(qs, keep_blank_values=keep_blank_values, _qsl=True)


def quote(s, *, safe='/', _plus=False):
    """Poor man's urllib.parse.quote() and .quote_plus()"""
    safe += '_.-~'
    if all(c.isalpha() or c.isdigit() or c in safe for c in s):
        return s
    encoded = bytearray()
    space = b'+' if _plus else b'%20'
    for c in s:
        if c.isalpha() or c.isdigit() or c in safe:
            encoded.append(ord(c))
        elif c == ' ':
            encoded.extend(space)
        else:
            for b in c.encode('utf-8'):
                hi, lo = (b >> 4), (b & 15)
                encoded.extend(bytes([37, hi + (48 if hi < 10 else 55), lo + (48 if lo < 10 else 55)]))
    return encoded.decode('ascii')


def quote_plus(s, *, safe=''):
    """Poor man's urllib.parse.quote_plus()"""
    return quote(s, safe=safe, _plus=True)


def unquote(s, *, _plus=False):
    """Poor man's urllib.parse.unquote()"""
    if not ('%' in s or (_plus and '+' in s)):
        return s
    encoded = bytearray()
    i = 0
    len_s = len(s)
    while i < len_s:
        c = s[i]
        if c == '%' and i + 2 < len_s:
            try:
                encoded.append(int(s[i+1:i+3], 16))
                i += 2
            except ValueError:
                encoded.extend(c.encode('utf-8'))
        elif c == '+' and _plus:
            encoded.append(32)
        else:
            encoded.extend(c.encode('utf-8'))
        i += 1
    return encoded.decode('utf-8')


def unquote_plus(s):
    """Poor man's urllib.parse.unquote_plus()"""
    return unquote(s, _plus=True)


def urlencode(data, *, quote_via=quote_plus, doseq=False):
    """Poor man's urllib.parse.urlencode()"""
    if isinstance(data, dict):
        data = data.items()
    parts = []
    for key, value in data:
        if doseq and isinstance(value, (list, tuple)):
            for item in value:
                parts.append(quote_via(key) + '=' + quote_via(item))
        else:
            parts.append(quote_via(key) + '=' + quote_via(value))
    return '&'.join(parts)
