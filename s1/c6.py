import base64
import c3, c4, c5

def hamming(x: bytes, y: bytes):
    # yikes... this `bin` makes me cringgge
    # rewrite this in c if it's warranted
    return sum([bin(xx ^ yy).count('1') for xx, yy in zip(x, y)])


def chunk(data: bytes, bytesize: int, chunki: int):
    return data[bytesize*chunki:bytesize*(chunki+1)]


def break_xor_key(data: bytes, override_keysize=None):
    candidate_keysizes = []
    if override_keysize is None:
        for keysize in range(2, 40):
            n = 0
            score = 0
            while (n + 1) * keysize < len(data):
                score += ((hamming(chunk(data, keysize, n),
                                   chunk(data, keysize, n + 1)))
                          / (8 * keysize))
                n += 1
            if n > 0:
                score /= n
                candidate_keysizes.append((score, keysize))

        candidate_keysizes.sort()


    else:
        candidate_keysizes = [(0, override_keysize)]

    print(candidate_keysizes)
    for _, keysize in candidate_keysizes:
        blocks = [data[i::keysize] for i in range(keysize)]

        key = []
        for block in blocks:
            _, key_char, _ = c4.break_xor(block)
            key.append(key_char)

        yield key, c5.encrypt_xor(data, bytes(key))

if __name__ == '__main__':
    assert hamming(b'this is a test', b'wokka wokka!!!') == 37
    with open('6.txt', 'r') as f:
        data = base64.b64decode(f.read())

    f = break_xor_key(data)
    key, plaintext = next(f)
    print(f"key: '{bytes(key).decode('ascii')}'")
    print(plaintext)
