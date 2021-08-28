class InvalidPaddingException(Exception):
    pass


def strip_pkcs7(data: bytes):
    last_byte = data[-1]
    if set(data[-last_byte:]) == {last_byte}:
        return data[:-last_byte]
    raise InvalidPaddingException()

if __name__ == '__main__':
    print(strip_pkcs7(b"ICE ICE BABY\x04\x04\x04\x04"))
    try:
        strip_pkcs7(b"ICE ICE BABY\x05\x05\x05\x05")
    except InvalidPaddingException:
        print('OK! Expected bad padding')
    else:
        assert False

    try:
        strip_pkcs7(b"ICE ICE BABY\x01\x02\x03\x04")
    except InvalidPaddingException:
        print('OK! Expected bad padding')
    else:
        assert False


