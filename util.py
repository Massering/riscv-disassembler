def printf(pattern, *args):
    return pattern % args


def byte_to_str(byte):
    return bin(byte)[2:].zfill(8)


def bytes_to_strs(b: bytes):
    arr = []
    for i in b:
        arr.append(byte_to_str(i))
    return arr


def to_int(bites_s: str):
    x = 0
    b = 1
    for i in range(len(bites_s) - 1):
        x += int(bites_s[~i], 16) * b
        b <<= 1
    x -= b * int(bites_s[0], 16)
    return x
