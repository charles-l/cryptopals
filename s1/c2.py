import base64
if __name__ == '__main__':
    a = bytes.fromhex('1c0111001f010100061a024b53535009181c')
    b = bytes.fromhex('686974207468652062756c6c277320657965')
    c = [a ^ b for a, b in zip(a, b)]
    print(bytes(c).hex())
