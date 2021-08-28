import secrets
import c9, c10
import random
from c12 import print_chunked

def gen_aes_key():
    return secrets.token_bytes(16)

key = gen_aes_key()

def fullstr(s):
    return ("comment1=cooking%20MCs;userdata=" +
            s.replace(';', '%3B').replace('=', '%3D') +
            ";comment2=%20like%20a%20pound%20of%20bacon")

def encode(s):
    plaintext = fullstr(s).encode('ascii')
    padded = c9.pad_pkcs7(plaintext, 16)
    return c10.cbc(padded, key, bytes(16), 'encrypt')

def authenticate(msg):
    plaintext = c10.cbc(msg, key, bytes(16), 'decrypt')
    print('authenticating: ', plaintext)
    # TODO: figure out how to circumvent decode errors...
    return b';admin=true;' in plaintext


if __name__ == '__main__':
    payload = ''
    print_chunked(fullstr(payload))

    ciphertext = encode(payload)
    p1 = b'%20MCs;userdata='
    target = b';admin=true;____'
    mod = bytes(c ^ p ^ t for c, p, t in zip(ciphertext, p1, target))
    print(mod)
    ciphertext = mod + ciphertext[16:]
    if authenticate(bytes(ciphertext)):
        print("VICTORY")
