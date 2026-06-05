import hashlib
import random

p = 101
k = 7
x = "test"
h_x = int.from_bytes(hashlib.sha256(x.encode()).digest(), 'big') % p
print(f"h_x: {h_x}")

# Client
r = 13 # gcd(13, 100) = 1
blinded = pow(h_x, r, p)
print(f"blinded: {blinded}")

# Server
signed = pow(blinded, k, p)
print(f"signed: {signed}")

# Client unblind
r_inv = pow(r, -1, p-1)
unblinded = pow(signed, r_inv, p)
print(f"unblinded: {unblinded}")

# Direct
direct = pow(h_x, k, p)
print(f"direct: {direct}")

assert unblinded == direct
