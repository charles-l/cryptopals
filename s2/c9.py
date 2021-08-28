def pad_pkcs7(data: bytes, blocksize: int):
    k = -(len(data) % -blocksize)

    if k > 255:
        raise Exception(f"can't pad for k > 255, {k=}")

    return data + bytes(k * [k])

def strip_pkcs7(data: bytes):
    last_byte = data[-1]
    if set(data[-last_byte:]) == {last_byte}:
        return data[:-last_byte]
    return data

if __name__ == '__main__':
    print(pad_pkcs7(b"YELLOW SUBMARINE", 20))
    print(strip_pkcs7(pad_pkcs7(b"YELLOW SUBMARINE", 20)))
