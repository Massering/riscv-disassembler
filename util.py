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
