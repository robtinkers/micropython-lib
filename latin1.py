
@micropython.viper
def _latin1_to_utf8(buf: ptr8, length: int, dst: ptr8) -> int:
    write = int(dst) != 0
    dstlen = 0
    i = 0
    while i < length:
        b = buf[i]
        if b < 128:
            if write:
                dst[dstlen] = b
            dstlen += 1
        elif b < 160:
            return -1
        else:
            if write:
                dst[dstlen+0] = 0xC0 | (b >> 6)
                dst[dstlen+1] = 0x80 | (b & 0x3F)
            dstlen += 2
        i += 1
    return dstlen

def _decode_latin1(buf):
    buflen = len(buf)
    if buflen == 0:
        return ''
    utf8len = _latin1_to_utf8(buf, buflen, 0)
    if utf8len < 0:
        raise UnicodeError
    if utf8len == buflen and hasattr(buf, "decode"):
        return buf.decode()
    utf8dst = bytearray(utf8len)
    _latin1_to_utf8(buf, buflen, utf8dst)
    return utf8dst.decode()

print(_decode_latin1(b'hello!'))
print(_decode_latin1(b'\xDF\xCA\x54\xC5'))
