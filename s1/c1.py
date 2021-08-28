import base64

def hex2b64(s):
    return base64.b64encode(bytes.fromhex(s))

if __name__ == '__main__':
    s = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    b = bytes.fromhex(s)
    print(base64.b64encode(b))

