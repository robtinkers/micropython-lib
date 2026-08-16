# string_ish.py
#
# String helpers for tiny devices.

_CHECK_OBJECT_TYPE = const(0)

if _CHECK_OBJECT_TYPE:
    _BYTES_LIKE = (bytes, bytearray, memoryview)

def _dispatch(func, haystack: object, needle: object, needle_len=None, flags=0):
    if isinstance(needle, str):
        needle = memoryview(needle)
    if needle_len is None or needle_len > len(needle):
        needle_len = len(needle)
    elif needle_len < 0:
        needle_len = max(0, len(needle) + needle_len)
    return func(haystack, needle, needle_len, flags)

@micropython.viper
def _to(buf: object, flags: int) -> int:
    if isinstance(buf, str):
        buf = memoryview(buf)
    elif _CHECK_OBJECT_TYPE and not isinstance(buf, _BYTES_LIKE):
        raise TypeError("buf")
    mutable = isinstance(buf, bytearray) or bool(flags & 128)

    buf_len = int(len(buf))
    buf_ptr = ptr8(buf)

    result = 0
    i = 0
    while i < buf_len:
        x = buf_ptr[i]
        if 65 <= x and x <= 90: # upper
            if (flags & 4):
                if mutable:
                    buf_ptr[i] = x + 32
                result += 1
        elif 97 <= x and x <= 122: # lower
            if (flags & 8):
                if mutable:
                    buf_ptr[i] = x - 32
                result += 1
        i += 1
    return result

def to_lower(buf: object, force: bool=False) -> int:
    return _to(buf, (128 if force else 0) | 4)

def to_upper(buf: object, force: bool=False) -> int:
    return _to(buf, (128 if force else 0) | 8)

@micropython.viper
def _all(buf: object, flags: int) -> bool:
    if isinstance(buf, str):
        buf = memoryview(buf)
    elif _CHECK_OBJECT_TYPE and not isinstance(buf, _BYTES_LIKE):
        raise TypeError("buf")

    buf_len = int(len(buf))
    buf_ptr = ptr8(buf)

    flags = ~flags
    i = 0
    while i < buf_len:
        x = buf_ptr[i]
        if x <= 31:
            if (flags & 1):
                return False
        elif 48 <= x and x <= 57: # digits
            if (flags & 2):
                return False
        elif 65 <= x and x <= 90: # upper
            if (flags & 4):
                return False
        elif 97 <= x and x <= 122: # lower
            if (flags & 8):
                return False
        elif x == 127:
            if (flags & 16):
                return False
        elif x >= 128:
            if (flags & 32):
                return False
        else:
            if (flags & 64):
                return False
        i += 1
    return True

def all_alpha(buf: object) -> bool:
    return _all(buf, 4|8)

def all_alnum(buf: object) -> bool:
    return _all(buf, 2|4|8)

def all_upper(buf: object) -> bool:
    return _all(buf, 4)

def all_lower(buf: object) -> bool:
    return _all(buf, 8)

def all_digit(buf: object) -> bool:
    return _all(buf, 2)

def all_print(buf: object) -> bool:
    return _all(buf, 2|4|8|64)

#def all_ascii(buf: object) -> bool:
#    return _all(buf, 1|2|4|8|16|64)

@micropython.viper
def all_ascii(buf: object) -> bool:
    if isinstance(buf, str):
        buf = memoryview(buf)
    elif _CHECK_OBJECT_TYPE and not isinstance(buf, _BYTES_LIKE):
        raise TypeError("buf")

    buf_len = int(len(buf))
    buf_ptr = ptr8(buf)

    i = 0
    while i < buf_len:
        if buf_ptr[i] >= 128:
            return False
        i += 1
    return True

@micropython.viper
def _strip(buf: object, flags: int) -> object:
    if _CHECK_OBJECT_TYPE and not isinstance(buf, _BYTES_LIKE):
        raise TypeError("buf")

    buf_len = int(len(buf))
    buf_ptr = ptr8(buf)

    start = 0
    end = buf_len
    if flags & 2:
        while end > start:
            if buf_ptr[end-1] > 32:
                break
            end -= 1
    if flags & 1:
        while start < end:
            if buf_ptr[start] > 32:
                break
            start += 1
    return (start, buf_len - end)

def lstrip(buf: object) -> int:
    return _strip(buf, 1)[0]

def rstrip(buf: object) -> int:
    return _strip(buf, 2)[1]

def strip(buf: object) -> tuple:
    return _strip(buf, 3)

@micropython.viper
def _find(haystack: object, needle_ptr: ptr8, needle_len: int, ci_flag: int) -> int:
    if _CHECK_OBJECT_TYPE and not isinstance(haystack, _BYTES_LIKE):
        raise TypeError("haystack")

    haystack_len = int(len(haystack))
    if needle_len == 0:
        return 0
    if needle_len < 0 or haystack_len < needle_len:
        return -1
    last_start = haystack_len - needle_len

    haystack_ptr = ptr8(haystack)
    first = needle_ptr[0]
    if ci_flag and 65 <= first and first <= 90:
        first += 32

    i = 0
    while i <= last_start:
        x = haystack_ptr[i]
        if ci_flag and 65 <= x and x <= 90:
            x += 32
        if x == first:
            j = 1
            while j < needle_len:
                x = haystack_ptr[i + j]
                y = needle_ptr[j]
                if x != y:
                    if ci_flag:
                        if 65 <= x and x <= 90:
                            x += 32
                        if 65 <= y and y <= 90:
                            y += 32
                    if x != y:
                        break
                j += 1
            if j == needle_len:
                return i
        i += 1
    return -1

def find(haystack: object, needle: object, needle_len=None) -> int:
    return _dispatch(_find, haystack, needle, needle_len, 0)

def find_ci(haystack: object, needle: object, needle_len=None) -> int:
    return _dispatch(_find, haystack, needle, needle_len, 1)

@micropython.viper
def _rfind(haystack: object, needle_ptr: ptr8, needle_len: int, ci_flag: int) -> int:
    if _CHECK_OBJECT_TYPE and not isinstance(haystack, _BYTES_LIKE):
        raise TypeError("haystack")

    haystack_len = int(len(haystack))
    if needle_len == 0:
        return haystack_len
    if needle_len < 0 or haystack_len < needle_len:
        return -1

    haystack_ptr = ptr8(haystack)
    first = needle_ptr[0]
    if ci_flag and 65 <= first and first <= 90:
        first += 32

    i = haystack_len - needle_len + 1
    while i > 0:
        i -= 1
        x = haystack_ptr[i]
        if ci_flag and 65 <= x and x <= 90:
            x += 32
        if x == first:
            j = 1
            while j < needle_len:
                x = haystack_ptr[i + j]
                y = needle_ptr[j]
                if x != y:
                    if ci_flag:
                        if 65 <= x and x <= 90:
                            x += 32
                        if 65 <= y and y <= 90:
                            y += 32
                    if x != y:
                        break
                j += 1
            if j == needle_len:
                return i
    return -1

def rfind(haystack: object, needle: object, needle_len=None) -> int:
    return _dispatch(_rfind, haystack, needle, needle_len, 0)

def rfind_ci(haystack: object, needle: object, needle_len=None) -> int:
    return _dispatch(_rfind, haystack, needle, needle_len, 1)

def contains(haystack: object, needle: object, needle_len=None) -> bool:
    if isinstance(haystack, str):
        haystack = memoryview(haystack)
    return (find(haystack, needle, needle_len) >= 0)

def contains_ci(haystack: object, needle: object, needle_len=None) -> bool:
    if isinstance(haystack, str):
        haystack = memoryview(haystack)
    return (find_ci(haystack, needle, needle_len) >= 0)

@micropython.viper
def countpins(haystack: object, pin: int) -> int:
    if isinstance(haystack, str):
        haystack = memoryview(haystack)
    elif _CHECK_OBJECT_TYPE and not isinstance(haystack, _BYTES_LIKE):
        raise TypeError("haystack")

    haystack_len = int(len(haystack))
    haystack_ptr = ptr8(haystack)

    result = 0
    i = 0
    while i < haystack_len:
        if haystack_ptr[i] == pin:
            result += 1
        i += 1
    return result

@micropython.viper
def findpin(haystack: object, pin: int) -> int:
    if _CHECK_OBJECT_TYPE and not isinstance(haystack, _BYTES_LIKE):
        raise TypeError("haystack")

    haystack_len = int(len(haystack))
    haystack_ptr = ptr8(haystack)

    i = 0
    while i < haystack_len:
        if haystack_ptr[i] == pin:
            return i
        i += 1
    return -1

@micropython.viper
def rfindpin(haystack: object, pin: int) -> int:
    if _CHECK_OBJECT_TYPE and not isinstance(haystack, _BYTES_LIKE):
        raise TypeError("haystack")

    haystack_len = int(len(haystack))
    haystack_ptr = ptr8(haystack)

    i = haystack_len
    while i > 0:
        i -= 1
        if haystack_ptr[i] == pin:
            return i
    return -1

@micropython.viper
def slice_findpin(haystack_ptr: ptr8, start: int, end: int, pin: int) -> int:
    while start < end:
        if haystack_ptr[start] == pin:
            return start
        start += 1
    return -1

@micropython.viper
def slice_rfindpin(haystack_ptr: ptr8, start: int, end: int, pin: int) -> int:
    while start < end:
        end -= 1
        if haystack_ptr[end] == pin:
            return end
    return -1

def containspin(haystack: object, pin: int) -> bool:
    if isinstance(haystack, str):
        haystack = memoryview(haystack)
    return (findpin(haystack, pin) >= 0)

def slice_containspin(haystack_ptr, start: int, end: int, pin: int) -> bool:
    return (slice_findpin(haystack_ptr, start, end, pin) >= 0)

@micropython.viper
def _equals(haystack: object, needle_ptr: ptr8, needle_len: int, ci_flag: int) -> bool:
    if isinstance(haystack, str):
        haystack = memoryview(haystack)
    elif _CHECK_OBJECT_TYPE and not isinstance(haystack, _BYTES_LIKE):
        raise TypeError("haystack")

    haystack_len = int(len(haystack))
    if haystack_len != needle_len:
        return False

    haystack_ptr = ptr8(haystack)

    i = 0
    while i < haystack_len:
        x = haystack_ptr[i]
        y = needle_ptr[i]
        if x != y:
            if ci_flag:
                if 65 <= x and x <= 90:
                    x += 32
                if 65 <= y and y <= 90:
                    y += 32
            if x != y:
                return False
        i += 1
    return True

def equals(haystack: object, needle: object, needle_len=None) -> bool:
    return _dispatch(_equals, haystack, needle, needle_len, 0)

def equals_ci(haystack: object, needle: object, needle_len=None) -> bool:
    return _dispatch(_equals, haystack, needle, needle_len, 1)

@micropython.viper
def slice_equals(haystack_ptr: ptr8, start: int, end: int, needle_ptr: ptr8) -> bool:
    i = start
    j = 0
    while i < end:
        if haystack_ptr[i] != needle_ptr[j]:
            return False
        i += 1
        j += 1
    return True

@micropython.viper
def _startswith(haystack: object, needle_ptr: ptr8, needle_len: int, flags: int) -> bool:
    if isinstance(haystack, str):
        haystack = memoryview(haystack)
    elif _CHECK_OBJECT_TYPE and not isinstance(haystack, _BYTES_LIKE):
        raise TypeError("haystack")

    haystack_len = int(len(haystack))
    haystack_ptr = ptr8(haystack)

    i = 0
    if flags & 2:
        while i < haystack_len and haystack_ptr[i] <= 32:
            i += 1

    if haystack_len - i < needle_len:
        return False

    haystack_len = i + needle_len
    needle_len = 0
    while i < haystack_len:
        x = haystack_ptr[i]
        y = needle_ptr[needle_len]
        if x != y:
            if flags & 1:
                if 65 <= x and x <= 90:
                    x += 32
                if 65 <= y and y <= 90:
                    y += 32
            if x != y:
                return False
        i += 1
        needle_len += 1
    return True

def startswith(haystack: object, needle: object, needle_len=None, *, trim=False) -> bool:
    return _dispatch(_startswith, haystack, needle, needle_len, 2 if trim else 0)

def startswith_ci(haystack: object, needle: object, needle_len=None, *, trim=False) -> bool:
    return _dispatch(_startswith, haystack, needle, needle_len, 3 if trim else 1)

@micropython.viper
def _endswith(haystack: object, needle_ptr: ptr8, needle_len: int, flags: int) -> bool:
    if isinstance(haystack, str):
        haystack = memoryview(haystack)
    elif _CHECK_OBJECT_TYPE and not isinstance(haystack, _BYTES_LIKE):
        raise TypeError("haystack")

    i = int(len(haystack))
    haystack_ptr = ptr8(haystack)

    if flags & 2:
        while i > 0 and haystack_ptr[i - 1] <= 32:
            i -= 1

    if i < needle_len:
        return False

    while needle_len > 0:
        i -= 1
        needle_len -= 1
        x = haystack_ptr[i]
        y = needle_ptr[needle_len]
        if x != y:
            if flags & 1:
                if 65 <= x and x <= 90:
                    x += 32
                if 65 <= y and y <= 90:
                    y += 32
            if x != y:
                return False
    return True

def endswith(haystack: object, needle: object, needle_len=None, *, trim=False) -> bool:
    return _dispatch(_endswith, haystack, needle, needle_len, 2 if trim else 0)

def endswith_ci(haystack: object, needle: object, needle_len=None, *, trim=False) -> bool:
    return _dispatch(_endswith, haystack, needle, needle_len, 3 if trim else 1)

@micropython.viper
def _containstoken(haystack: object, needle_ptr: ptr8, needle_len: int, ci_flag: int) -> bool:
    if isinstance(haystack, str):
        haystack = memoryview(haystack)
    elif _CHECK_OBJECT_TYPE and not isinstance(haystack, _BYTES_LIKE):
        raise TypeError("haystack")

    haystack_len = int(len(haystack))
    if needle_len == 0:
        return False
    if needle_len < 0 or haystack_len < needle_len:
        return False
    last_start = haystack_len - needle_len

    haystack_ptr = ptr8(haystack)

    i = 0
    while i <= last_start:
        x = haystack_ptr[i]
        y = needle_ptr[0]
        if x != y:
            if ci_flag:
                if 65 <= x and x <= 90:
                    x += 32
                if 65 <= y and y <= 90:
                    y += 32
            if x != y:
                i += 1
                continue

        # Candidate must begin at a token boundary.
        if i:
            x = haystack_ptr[i - 1]
            if ((48 <= x and x <= 57)
                or (65 <= x and x <= 90)
                or (97 <= x and x <= 122)
                or x == 45 or x == 46 or x == 95
            ):
                i += 1
                continue

        # Candidate must end at a token boundary.
        j = i + needle_len
        if j < haystack_len:
            x = haystack_ptr[j]
            if ((48 <= x and x <= 57)
                or (65 <= x and x <= 90)
                or (97 <= x and x <= 122)
                or x == 45 or x == 46 or x == 95
            ):
                i += 1
                continue

        j = 1
        while j < needle_len:
            x = haystack_ptr[i + j]
            y = needle_ptr[j]
            if x != y:
                if ci_flag:
                    if 65 <= x and x <= 90:
                        x += 32
                    if 65 <= y and y <= 90:
                        y += 32
                if x != y:
                    break
            j += 1

        if j == needle_len:
            return True
        i += 1

    return False

def containstoken(haystack: object, needle: object, needle_len=None) -> bool:
    return _dispatch(_containstoken, haystack, needle, needle_len, 0)

def containstoken_ci(haystack: object, needle: object, needle_len=None) -> bool:
    return _dispatch(_containstoken, haystack, needle, needle_len, 1)

@micropython.viper
def slice_uint(buf_ptr: ptr8, start: int, end: int, base: int) -> int:
    if base < 2 or base > 36:
        return -1

    while start < end and buf_ptr[start] <= 32:
        start += 1
    if start == end:
        return -1

    cutoff = 0x3FFFFFFF // base
    cutlim = 0x3FFFFFFF - cutoff * base

    value = 0
    while start < end:
        char = buf_ptr[start]
        if 48 <= char and char <= 57:
            digit = char - 48
        elif 65 <= char and char <= 90:
            digit = char - 65 + 10
        elif 97 <= char and char <= 122:
            digit = char - 97 + 10
        else:
            while start < end:
                if buf_ptr[start] > 32:
                    return -1
                start += 1
            return value
        if digit >= base:
            return -1
        if value > cutoff or (value == cutoff and digit > cutlim):
            return -1
        value = value * base + digit
        start += 1

    return value

def parse_uint(buf: object, base: int=10) -> int:
    return slice_uint(buf, 0, len(buf), base)	
