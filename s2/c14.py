import secrets
import base64
from Crypto.Cipher import AES
from boltons.iterutils import chunked
from collections import Counter
import c9
from c12 import print_chunked

message = '''Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK'''

key = b'v\xd7\x92X\xd1\x0f[YK\xffA\x83\x14\x1c\xed\xc9'
random_prefix = secrets.token_bytes(secrets.randbelow(17))

def encryption_oracle(data: bytes):
    aes = AES.AESCipher(c9.pad_pkcs7(key, 16))
    return aes.encrypt(c9.pad_pkcs7(random_prefix + data + base64.b64decode(message), 16))

def break_ecb(encryption_oracle):
    # find blocksize
    t = 0
    initial_len = len(encryption_oracle(b''))
    while len(encryption_oracle(b'a' * t)) == initial_len:
        t += 1
    blocksize = len(encryption_oracle(b'a' * t)) - initial_len

    # determine if ecb mode is being used
    counter = Counter(chunked(encryption_oracle(b'a' * 64), 16))
    if not any(x > 1 for x in counter.values()):
        raise Exception("first two blocks don't match -- either there's a header or ecb mode isn't being used")

    # find the prefix length
    for i in range(blocksize*3+1):
        prefix, a, b, *rest = chunked(encryption_oracle(b'A' * i), blocksize)
        if a == b:
            break
    prefix_len = (blocksize*3) - i
    prefix_padding = blocksize-prefix_len

    prefix, a, b, *rest = chunked(encryption_oracle(b'P' * prefix_padding + (b'A' * blocksize * 3)), blocksize)
    assert a == b

    nblocks = int(initial_len / blocksize)
    hidden_msg_len = initial_len - t + 1 - prefix_len

    def get_chunk(ciphertext, chunki):
        return encryption_oracle(ciphertext)[chunki*blocksize:(chunki+1)*blocksize]

    known = b''
    for blocki in range(1, nblocks):
        for i in range(1, blocksize+1):
            lookup = {}
            for j in range(256):
                k = b'P' * prefix_padding + b'A' * (blocksize-i) + known + bytes([j])
                lookup[get_chunk(k, blocki)] = bytes([j])
            test = b'P' * prefix_padding +b'A' * (blocksize-i)
            known += lookup[get_chunk(test, blocki)]

            if len(known) == hidden_msg_len:
                return known

if __name__ == '__main__':
    print(break_ecb(encryption_oracle))
