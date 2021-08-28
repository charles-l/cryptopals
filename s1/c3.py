from collections import Counter
import math

s = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
b = bytes.fromhex(s)

# spaces are slightly more frequent than all other letters
# sorta based on http://pi.math.cornell.edu/~mec/2003-2004/cryptography/subs/frequencies.html
_freq_table_rows = '''\
  23000
E 21912
T 16587
A 14810
O 14003
I 13318
N 12666
S 11450
R 10977
H 10795
D 7874
L 7253
U 5246
C 4943
M 4761
F 4200
Y 3853
W 3819
G 3693
P 3316
B 2715
V 2019
K 1257
X 315
Q 205
J 188
Z 128'''.split('\n')
_count_table = {r[0].lower(): int(r[2:]) for r in _freq_table_rows}
_sum = sum(_count_table.values())
freq_table = {k: v/_sum for k, v in _count_table.items()}

def evaluate(candidate: str):
    assert isinstance(candidate, str)
    counts = Counter(candidate.lower())
    coeff = sum(math.sqrt((freq_table.get(char, 0) * y)/len(candidate))
                for char, y in counts.items())
    return coeff

if __name__ == '__main__':
    s = bytes.fromhex('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
    best = (float('-inf'), '')
    for b in range(255):
        try:
            r = bytes([b ^ c for c in s]).decode('ascii')
            score = evaluate(r)
            print(score, r)
            if score > best[0]:
                best = (score, r)
        except UnicodeDecodeError:
            pass
    print(best)
