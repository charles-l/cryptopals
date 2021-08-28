import string
import secrets
import base64
from Crypto.Cipher import AES
from boltons.iterutils import chunked
import c9
from typing import Union

message = '''Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK'''

key = b'v\xd7\x92X\xd1\x0f[YK\xffA\x83\x14\x1c\xed\xc9'

def encryption_oracle(data: bytes):
    aes = AES.AESCipher(c9.pad_pkcs7(key, 16))
    return aes.encrypt(c9.pad_pkcs7(data + base64.b64decode(message), 16))

def print_chunked(x: Union[str, bytes], chunksize=16, newlines=False):
    if isinstance(x, str):
        print(' '.join(chunked(''.join(c if c in string.printable else '.' for c in x).replace(' ', '.').replace('\n', '.'), chunksize)) + f' ({len(x)})')
    elif isinstance(x, bytes):
        print_chunked(x.hex(), 2*chunksize)
    else:
        assert False

def break_ecb(encryption_oracle):
    # find blocksize
    t = 0
    initial_len = len(encryption_oracle(b''))
    while len(encryption_oracle(b'a' * t)) == initial_len:
        t += 1
    blocksize = len(encryption_oracle(b'a' * t)) - initial_len

    hidden_msg_len = initial_len - t + 1

    # determine if ecb mode is being used (could also check for duplicates in a set)
    a, b, *junk = chunked(encryption_oracle(b'a' * 64), 16)
    if a != b:
        raise Exception("first two blocks don't match -- either there's a header or ecb mode isn't being used")

    def get_chunk(ciphertext, chunki):
        return encryption_oracle(ciphertext)[chunki*blocksize:(chunki+1)*blocksize]

    nblocks = int(initial_len / blocksize)


    known = b''
    for blocki in range(nblocks):
        for i in range(1, blocksize+1):
            lookup = {}
            for j in range(256):
                k = b'A' * (blocksize-i) + known + bytes([j])
                lookup[get_chunk(k, blocki)] = bytes([j])
            test = b'A' * (blocksize-i)
            known += lookup[get_chunk(test, blocki)]

            if len(known) == hidden_msg_len:
                return known

if __name__ == '__main__':
    print(break_ecb(encryption_oracle))
