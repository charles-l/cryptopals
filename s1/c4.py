from typing import Iterable
import c3

with open('4.txt', 'r') as f:
    lines = [x.strip() for x in f.readlines()]

def histogram(s: bytes, candidates: Iterable):
    scores = {}
    for k in candidates:
        try:
            r = bytes([k ^ c for c in s]).decode('ascii')
            scores[chr(k)] = c3.evaluate(r)
        except UnicodeDecodeError:
            pass
    return sorted(scores.items(), key=lambda x: x[1], reverse=True)


def break_xor(s: bytes):
    best = (0, 0)
    for k in range(255):
        try:
            r = bytes([k ^ c for c in s]).decode('ascii')
            score = c3.evaluate(r)
            if score > best[0]:
                best = (score, k)
        except UnicodeDecodeError:
            pass
    return best[0], best[1], bytes([best[1] ^ c for c in s])

if __name__ == '__main__':
    best = (0, 0, b'')
    for l in lines:
        c = break_xor(bytes.fromhex(l))
        best = max(c, best)
    print(best)
