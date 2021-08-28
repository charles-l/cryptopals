import secrets
import c9, c10
from Crypto.Cipher import AES
from boltons.iterutils import chunked

def gen_aes_key():
    return secrets.token_bytes(16)

def encryption_oracle(data: bytes):
    key = gen_aes_key()
    before = secrets.token_bytes(secrets.randbelow(6) + 5)
    after = secrets.token_bytes(secrets.randbelow(6) + 5)
    if secrets.randbelow(2) == 0:
        aes = AES.AESCipher(c9.pad_pkcs7(key, 16))
        return aes.encrypt(c9.pad_pkcs7(before + data + after, 16))
    else:
        return c10.cbc(before + data + after, key, gen_aes_key(), 'encrypt')

def detect_encryption(encryptf):
    data = b'A' * 43
    ciphertext = encryptf(data)
    _, a, b, _ = chunked(ciphertext, 16)
    if a == b:
        return 'ecb'
    else:
        return 'cbc'

if __name__ == '__main__':
    print(detect_encryption(encryption_oracle))

