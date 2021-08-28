import c9
from Crypto.Cipher import AES
from boltons.iterutils import chunked
from typing import Literal, Callable, cast

Mode = Literal['encrypt', 'decrypt']
def cbc(plaintext: bytes, key: bytes, iv: bytes, mode: Mode):
    key = c9.pad_pkcs7(key, 16)
    plaintext = c9.pad_pkcs7(plaintext, 16)
    chunks = chunked(plaintext, 16)
    aes = AES.AESCipher(key)

    prev = iv
    r = b''
    for chunk in chunks:
        if mode == 'encrypt':
            cipherblock = aes.encrypt(bytes([a ^ b for a, b in zip(prev, chunk)]))
            prev = cipherblock
            r += cipherblock
        elif mode == 'decrypt':
            plaintext = bytes([a ^ b for a, b in zip(prev, aes.decrypt(chunk))])
            r += plaintext
            prev = chunk
        else:
            assert False
    return bytes(r)

if __name__ == '__main__':
    ciphertext = cbc(b"This is some plaintext that no one will see", b"A KEY!", bytes(16), 'encrypt')
    print(ciphertext)
    plaintext = cbc(ciphertext, b"A KEY!", bytes(16), 'decrypt')
    print(plaintext)

    import base64
    with open('10.txt', 'r') as f:
        data = base64.b64decode(f.read())
        print(cbc(data, b'YELLOW SUBMARINE', bytes(16), 'decrypt'))

