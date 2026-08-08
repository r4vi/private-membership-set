import math
import random

# Full RFC 3526 2048-bit MODP group (Group 14) prime.
# Safe prime: p = 2q + 1 with q prime. The previous version of this file used
# a truncated, typo'd copy of this constant (...8E34041B instead of
# ...8E3404DD EF9519B3 ... FFFFFFFF FFFFFFFF), which is composite, so Fermat's
# little theorem did not hold and OPRF unblinding produced wrong results.
p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF


def test_dh_oprf_large_prime():
    """The DH OPRF must recover H(x)^k after blind -> sign -> unblind.

    Unblinding relies on Fermat's little theorem, i.e. on p being prime.
    Regression test: the previous version of this file used a truncated
    composite "prime" and only printed the result (no assert), so pytest
    reported PASS while the protocol was broken.
    """
    random.seed(0)
    for _ in range(25):
        h_x = random.randint(2, p - 1)
        k = random.randint(2, p - 1)
        while True:
            r = random.randint(2, p - 1)
            if math.gcd(r, p - 1) == 1:
                break

        blinded = pow(h_x, r, p)
        signed = pow(blinded, k, p)
        r_inv = pow(r, -1, p - 1)
        unblinded = pow(signed, r_inv, p)
        direct = pow(h_x, k, p)

        assert unblinded == direct, (
            f"OPRF unblinding failed for p={p}: "
            f"unblinded={unblinded}, direct={direct}"
        )
