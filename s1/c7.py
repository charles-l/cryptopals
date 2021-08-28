import base64
from Crypto.Cipher import AES

if __name__ == '__main__':
    with open('7.txt', 'r') as f:
        ciphertext = base64.b64decode(f.read())

    key = 'YELLOW SUBMARINE'
    aes = AES.AESCipher(key)
    print(aes.decrypt(ciphertext))
