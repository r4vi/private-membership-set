p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E34041B
import math
import random

def test():
    h_x = random.randint(2, p-1)
    k = random.randint(2, p-1)
    while True:
        r = random.randint(2, p-1)
        if math.gcd(r, p-1) == 1:
            break
    
    blinded = pow(h_x, r, p)
    signed = pow(blinded, k, p)
    r_inv = pow(r, -1, p-1)
    unblinded = pow(signed, r_inv, p)
    direct = pow(h_x, k, p)
    
    print(f"Match: {unblinded == direct}")

test()
