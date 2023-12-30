def printf(pattern, *args):
    try:
        return pattern % args
    except:
        return 'Error while format: ', '"' + pattern + '"', *args


def byte_to_str(b):
    return bin(b)[2:].zfill(8)


def bytes_to_strs(b: bytes):
    p = []
    for i in b:
        p.append(byte_to_str(i))
    return p


def to_int(bites_s: str):
    x = 0
    b = 1
    for i in range(len(bites_s) - 1):
        x += int(bites_s[~i], 16) * b
        b <<= 1
    x -= b * int(bites_s[0], 16)
    return x
