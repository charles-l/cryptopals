import c9
from c12 import print_chunked
from Crypto.Cipher import AES
from boltons.iterutils import chunked

def decode_param(s):
    return dict(x.split('=') for x in s.split('&'))

def encode_param(d):
    return '&'.join('='.join(str(y) for y in x) for x in d.items())

def profile_for(email):
    return encode_param({'email': email.replace('&', '').replace('=', ''),
                         'uid': 2,
                         'role': 'user'})

def do_encrypt(msg: bytes):
    assert isinstance(msg, bytes)
    key = b"I\xd3T\xd6\x93x\n>\xd0\xde'\xec2\xf9\x95\x8c"
    aes = AES.AESCipher(key)
    return aes.encrypt(c9.pad_pkcs7(msg, 16))

def do_decrypt(msg: bytes):
    key = b"I\xd3T\xd6\x93x\n>\xd0\xde'\xec2\xf9\x95\x8c"
    aes = AES.AESCipher(key)
    plaintext = c9.strip_pkcs7(aes.decrypt(msg)).decode('ascii')
    return decode_param(plaintext)

def oracle(msg: str):
    return do_encrypt(profile_for(msg).encode('ascii'))

def debug(payload):
    print(f'{payload=}')
    full_msg = f'email={payload}&uid=2&role=user'
    print_chunked(oracle(payload))
    print_chunked(full_msg)
    print_chunked(c9.pad_pkcs7(bytes(full_msg, 'ascii'), 16))

if __name__ == '__main__':
    assert decode_param('foo=bar&baz=qux&zap=zazzle') == {'foo': 'bar', 'baz': 'qux', 'zap': 'zazzle'}

    # with this payload, the last chunk can be controlled by us
    payload = 'A'*46
    debug('A'*46)

    admin_chunk = chunked(oracle((b'AAAAAAAAAA' + c9.pad_pkcs7(b'admin', 16)).decode('ascii')), 16)[1]
    payload = oracle('charles@gmail.com'.ljust(46))
    chunks = chunked(payload, 16)
    chunks[4] = admin_chunk
    print(do_decrypt(b''.join(chunks)))
