import c3
from boltons.iterutils import chunked
from collections import Counter

if __name__ == '__main__':
    with open('8.txt', 'r') as f:
        ciphertexts = [bytes.fromhex(x.strip()) for x in f.readlines()]

    chunks = [set(chunked(t, 16)) for t in ciphertexts]
    print([(c[0], len(c[1])) for c in sorted(enumerate(chunks), key=lambda x: len(x[1]))])
