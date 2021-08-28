import itertools
import textwrap
def encrypt_xor(msg: bytes, key: bytes):
    return bytes([m ^ k for m, k in zip(msg, itertools.cycle(key))])

if __name__ == '__main__':
    msg = textwrap.dedent('''\
        Burning 'em, if you ain't quick and nimble
        I go crazy when I hear a cymbal''')

    print(encrypt_xor(bytes(msg, 'ascii'), bytes('ICE', 'ascii')).hex())
