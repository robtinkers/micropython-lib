# string_ish.py

@micropython.viper
def upper(buf: object, writeable: int) -> int:
    if isinstance(buf, str):
        buf = memoryview(buf)

    buf_len = int(len(buf))
    buf_ptr = ptr8(buf)
    result = 0
    i = 0
    while i < buf_len:
        x = buf_ptr[i]
        if 97 <= x and x <= 122:
            if writeable:
                buf_ptr[i] = x - 32
            result += 1
        i += 1
    return result

@micropython.viper
def lower(buf: object, writeable: int) -> int:
    if isinstance(buf, str):
        buf = memoryview(buf)

    buf_len = int(len(buf))
    buf_ptr = ptr8(buf)
    result = 0
    i = 0
    while i < buf_len:
        x = buf_ptr[i]
        if 65 <= x and x <= 90:
            if writeable:
                buf_ptr[i] = x + 32
            result += 1
        i += 1
    return result

@micropython.viper
def _find(haystack: object, needle_ptr: ptr8, needle_len: int, ci_flag: int) -> int:
    if isinstance(haystack, str):
        return -1

    if needle_len == 0:
        return 0
    haystack_len = int(len(haystack))
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

def find(haystack: object, needle: object, needle_len=None, *, _flags=0) -> int:
    if isinstance(needle, str):
        if needle_len is None:
            needle = memoryview(needle)
        else:
            needle = memoryview(needle[:needle_len]) # ugh
        needle_len = len(needle)
    elif needle_len is None or needle_len > len(needle):
        needle_len = len(needle)
    elif needle_len < 0:
        needle_len = max(0, len(needle) + needle_len)
    return _find(haystack, needle, needle_len, _flags)

def find_ci(haystack: object, needle: object, needle_len=None) -> int:
    return find(haystack, needle, needle_len, _flags=1)

def contains(haystack: object, needle: object, needle_len=None) -> int:
    if isinstance(haystack, str):
        haystack = memoryview(haystack)
    return 1 if find(haystack, needle, needle_len) >= 0 else 0

def contains_ci(haystack: object, needle: object, needle_len=None) -> int:
    if isinstance(haystack, str):
        haystack = memoryview(haystack)
    return 1 if find(haystack, needle, needle_len, _flags=1) >= 0 else 0

@micropython.viper
def findpin(haystack: object, pin: int) -> int:
    if isinstance(haystack, str):
        return -1

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
    if isinstance(haystack, str):
        return -1

    haystack_len = int(len(haystack))
    haystack_ptr = ptr8(haystack)

    while haystack_len:
        haystack_len -= 1
        if haystack_ptr[haystack_len] == pin:
            return haystack_len
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

def containspin(haystack: object, pin: int) -> int:
    if isinstance(haystack, str):
        haystack = memoryview(haystack)
    return 1 if findpin(haystack, pin) >= 0 else 0

def slice_containspin(haystack_ptr, start: int, end: int, pin: int) -> int:
    return 1 if slice_findpin(haystack_ptr, start, end, pin) >= 0 else 0

@micropython.viper
def _equals(haystack: object, needle_ptr: ptr8, needle_len: int, ci_flag: int) -> int:
    if isinstance(haystack, str):
        haystack = memoryview(haystack)

    haystack_len = int(len(haystack))
    if haystack_len != needle_len:
        return 0

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
                return 0
        i += 1
    return 1

def equals(haystack: object, needle: object, needle_len=None, *, _flags=0) -> int:
    if isinstance(needle, str):
        if needle_len is None:
            needle = memoryview(needle)
        else:
            needle = memoryview(needle[:needle_len]) # ugh
        needle_len = len(needle)
    elif needle_len is None or needle_len > len(needle):
        needle_len = len(needle)
    elif needle_len < 0:
        needle_len = max(0, len(needle) + needle_len)
    return _equals(haystack, needle, needle_len, _flags)

def equals_ci(haystack: object, needle: object, needle_len=None) -> int:
    return equals(haystack, needle, needle_len, _flags=1)

@micropython.viper
def slice_equals(haystack_ptr: ptr8, start: int, end: int, needle_ptr: ptr8) -> int:
    i = start
    j = 0
    while i < end:
        if haystack_ptr[i] != needle_ptr[j]:
            return 0
        i += 1
        j += 1
    return 1

@micropython.viper
def _startswith(haystack: object, needle: object, ci_flag: int) -> int:
    if isinstance(haystack, str):
        haystack = memoryview(haystack)
    if isinstance(needle, str):
        needle = memoryview(needle)

    haystack_len = int(len(haystack))
    needle_len = int(len(needle))
    if haystack_len < needle_len:
        return 0

    haystack_ptr = ptr8(haystack)
    needle_ptr = ptr8(needle)

    i = 0
    while i < needle_len:
        x = haystack_ptr[i]
        y = needle_ptr[i]
        if x != y:
            if ci_flag:
                if 65 <= x and x <= 90:
                    x += 32
                if 65 <= y and y <= 90:
                    y += 32
            if x != y:
                return 0
        i += 1
    return 1

def startswith(haystack: object, needle: object) -> int:
    return _startswith(haystack, needle, 0)

def startswith_ci(haystack: object, needle: object) -> int:
    return _startswith(haystack, needle, 1)

@micropython.viper
def _endswith(haystack: object, needle: object, ci_flag: int) -> int:
    if isinstance(haystack, str):
        haystack = memoryview(haystack)
    if isinstance(needle, str):
        needle = memoryview(needle)

    i = int(len(haystack))
    j = int(len(needle))
    if i < j:
        return 0

    haystack_ptr = ptr8(haystack)
    needle_ptr = ptr8(needle)

    while j:
        i -= 1
        j -= 1
        x = haystack_ptr[i]
        y = needle_ptr[j]
        if x != y:
            if ci_flag:
                if 65 <= x and x <= 90:
                    x += 32
                if 65 <= y and y <= 90:
                    y += 32
            if x != y:
                return 0
    return 1

def endswith(haystack: object, needle: object) -> int:
    return _endswith(haystack, needle, 0)

def endswith_ci(haystack: object, needle: object) -> int:
    return _endswith(haystack, needle, 1)

@micropython.viper
def _containstoken(haystack: object, needle_ptr: ptr8, needle_len: int, ci_flag: int) -> int:
    if isinstance(haystack, str):
        haystack = memoryview(haystack)

    if needle_len == 0:
        return 0
    haystack_len = int(len(haystack))
    if needle_len < 0 or haystack_len < needle_len:
        return 0
    last_start = haystack_len - needle_len

    haystack_ptr = ptr8(haystack)

    i = 0
    while i <= last_start:
        # Candidate must begin at a token boundary.
        if i:
            x = haystack_ptr[i - 1]
            if ((48 <= x and x <= 57)
                or (65 <= x and x <= 90)
                or (97 <= x and x <= 122)
                or x == 45 or x == 46 or x == 95 # -._
            ):
                i += 1
                continue
        # Candidate must end at a token boundary.
        after = i + needle_len
        if after < haystack_len:
            x = haystack_ptr[after]
            if ((48 <= x and x <= 57)
                or (65 <= x and x <= 90)
                or (97 <= x and x <= 122)
                or x == 45 or x == 46 or x == 95 # -._
            ):
                i += 1
                continue
        # Test candidate
        j = 0
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
            return 1
        i += 1
    return 0

def containstoken(haystack: object, needle: object, needle_len=None, *, _flags=0) -> int:
    if isinstance(needle, str):
        if needle_len is None:
            needle = memoryview(needle)
        else:
            needle = memoryview(needle[:needle_len]) # ugh
        needle_len = len(needle)
    elif needle_len is None or needle_len > len(needle):
        needle_len = len(needle)
    elif needle_len < 0:
        needle_len = max(0, len(needle) + needle_len)
    return _containstoken(haystack, needle, needle_len, _flags)

def containstoken_ci(haystack: object, needle: object, needle_len=None) -> int:
    return containstoken(haystack, needle, needle_len, _flags=1)
