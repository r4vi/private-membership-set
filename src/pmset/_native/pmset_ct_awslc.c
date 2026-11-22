/*
 * pmset_ct_awslc.c — AWS-LC (s2n-bignum formally verified) Constant-Time Provider for `pmset`.
 *
 * Designed specifically for AWS-LC (BoringSSL-derived libcrypto):
 *   - Enforces `#ifdef OPENSSL_IS_AWSLC` at compile time.
 *   - Links statically against AWS-LC `libcrypto.a` with `-fvisibility=hidden
 *     -Wl,-Bsymbolic -Wl,--exclude-libs,ALL` so ONLY `pmset_ct_*` symbols are
 *     exported — zero symbol collision with Python's system OpenSSL `libcrypto.so`.
 *   - Uses AWS-LC's s2n-bignum HOL Light formally verified constant-time P-256
 *     scalar multiplication (`EC_POINT_mul` on `NID_X9_62_prime256v1`) and
 *     constant-time Montgomery exponentiation (`BN_mod_exp_mont_consttime`).
 *   - Implements Joye constant-bit-length exponent padding using fixed-width
 *     byte buffers + branchless `pmset_ct_select_bytes`.
 *   - Uses `BN_mod_inverse_blinded` (constant-time blinded inversion) when `mod`
 *     is odd, and `BN_mod_inverse` otherwise.
 *   - Cleanses all transient secret buffers via `OPENSSL_cleanse` / `BN_clear_free`.
 */

#include "pmset_ct.h"

#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/mem.h>
#include <openssl/nid.h>
#include <openssl/opensslv.h>

#ifndef OPENSSL_IS_AWSLC
#error "pmset_ct_awslc.c must be compiled against AWS-LC headers (OPENSSL_IS_AWSLC not defined)"
#endif

static void ensure_awslc_init(void) {
    static int initialized = 0;
    if (!initialized) {
        CRYPTO_library_init();
        initialized = 1;
    }
}

const char *pmset_ct_provider_name(void) {
    return "aws-lc";
}

const char *pmset_ct_provider_version(void) {
    ensure_awslc_init();
#ifdef AWSLC_VERSION_NUMBER_STRING
    return "AWS-LC " AWSLC_VERSION_NUMBER_STRING " (s2n-bignum)";
#else
    return OpenSSL_version(OPENSSL_VERSION);
#endif
}

const char *pmset_ct_openssl_version(void) {
    return pmset_ct_provider_version();
}

int pmset_ct_modexp(
    const uint8_t *base, size_t base_len,
    const uint8_t *exp, size_t exp_len,
    const uint8_t *mod, size_t mod_len,
    uint8_t *out, size_t out_len) {
    ensure_awslc_init();
    int rc = -1;
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *bn_base = NULL, *bn_exp = NULL, *bn_mod = NULL, *bn_res = NULL;
    if (!ctx) goto cleanup;

    bn_base = BN_bin2bn(base, base_len, NULL);
    bn_exp = BN_bin2bn(exp, exp_len, NULL);
    bn_mod = BN_bin2bn(mod, mod_len, NULL);
    bn_res = BN_new();
    if (!bn_base || !bn_exp || !bn_mod || !bn_res) goto cleanup;

    if (!BN_is_odd(bn_mod) || BN_is_zero(bn_mod) || BN_is_one(bn_mod)) {
        rc = -2;
        goto cleanup;
    }

    if (BN_mod_exp_mont_consttime(bn_res, bn_base, bn_exp, bn_mod, ctx, NULL) != 1) {
        rc = -3;
        goto cleanup;
    }

    if (BN_bn2bin_padded(out, out_len, bn_res) != 1) {
        rc = -4;
        goto cleanup;
    }
    rc = 0;

cleanup:
    BN_clear_free(bn_base);
    BN_clear_free(bn_exp);
    BN_clear_free(bn_mod);
    BN_clear_free(bn_res);
    BN_CTX_free(ctx);
    return rc;
}

int pmset_ct_modexp_order(
    const uint8_t *base, size_t base_len,
    const uint8_t *exp, size_t exp_len,
    const uint8_t *order, size_t order_len,
    const uint8_t *mod, size_t mod_len,
    uint8_t *out, size_t out_len) {
    ensure_awslc_init();
    int rc = -1;
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *bn_base = NULL, *bn_exp = NULL, *bn_ord = NULL, *bn_mod = NULL;
    BIGNUM *e1 = NULL, *e2 = NULL, *bn_padded = NULL, *bn_res = NULL;
    uint8_t *buf1 = NULL, *buf2 = NULL, *buf_sel = NULL;
    size_t pad_bytes = order_len + 2;
    if (!ctx) goto cleanup;

    bn_base = BN_bin2bn(base, base_len, NULL);
    bn_exp = BN_bin2bn(exp, exp_len, NULL);
    bn_ord = BN_bin2bn(order, order_len, NULL);
    bn_mod = BN_bin2bn(mod, mod_len, NULL);
    e1 = BN_new();
    e2 = BN_new();
    bn_res = BN_new();
    buf1 = (uint8_t *)calloc(pad_bytes, 1);
    buf2 = (uint8_t *)calloc(pad_bytes, 1);
    buf_sel = (uint8_t *)calloc(pad_bytes, 1);
    if (!bn_base || !bn_exp || !bn_ord || !bn_mod || !e1 || !e2 || !bn_res ||
        !buf1 || !buf2 || !buf_sel) {
        goto cleanup;
    }

    if (!BN_is_odd(bn_mod) || BN_is_zero(bn_ord)) { rc = -2; goto cleanup; }

    /* Joye constant-bit-length exponent padding:
     * e1 = (exp mod ord) + ord; e2 = e1 + ord.
     * Select e1 if bit L is set, else e2, via branchless pmset_ct_select_bytes. */
    unsigned int L = BN_num_bits(bn_ord);
    if (BN_mod(bn_exp, bn_exp, bn_ord, ctx) != 1) { rc = -3; goto cleanup; }
    if (BN_add(e1, bn_exp, bn_ord) != 1) { rc = -3; goto cleanup; }
    if (BN_add(e2, e1, bn_ord) != 1) { rc = -3; goto cleanup; }

    if (BN_bn2bin_padded(buf1, pad_bytes, e1) != 1) { rc = -3; goto cleanup; }
    if (BN_bn2bin_padded(buf2, pad_bytes, e2) != 1) { rc = -3; goto cleanup; }

    uint8_t carry = (uint8_t)(BN_is_bit_set(e1, (int)L) & 1);
    /* select_b = 1 when carry == 0 (pick e2), 0 when carry == 1 (pick e1) */
    pmset_ct_select_bytes(buf_sel, buf1, buf2, pad_bytes, (uint8_t)(carry ^ 1u));

    bn_padded = BN_bin2bn(buf_sel, pad_bytes, NULL);
    if (!bn_padded) { rc = -3; goto cleanup; }

    if (BN_mod_exp_mont_consttime(bn_res, bn_base, bn_padded, bn_mod, ctx, NULL) != 1) {
        rc = -4;
        goto cleanup;
    }
    if (BN_bn2bin_padded(out, out_len, bn_res) != 1) {
        rc = -5;
        goto cleanup;
    }
    rc = 0;

cleanup:
    if (buf1) { OPENSSL_cleanse(buf1, pad_bytes); free(buf1); }
    if (buf2) { OPENSSL_cleanse(buf2, pad_bytes); free(buf2); }
    if (buf_sel) { OPENSSL_cleanse(buf_sel, pad_bytes); free(buf_sel); }
    BN_clear_free(bn_base);
    BN_clear_free(bn_exp);
    BN_clear_free(bn_ord);
    BN_clear_free(bn_mod);
    BN_clear_free(e1);
    BN_clear_free(e2);
    BN_clear_free(bn_padded);
    BN_clear_free(bn_res);
    BN_CTX_free(ctx);
    return rc;
}

int pmset_ct_modinv(
    const uint8_t *a, size_t a_len,
    const uint8_t *mod, size_t mod_len,
    uint8_t *out, size_t out_len) {
    ensure_awslc_init();
    int rc = -1;
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *bn_a = NULL, *bn_mod = NULL, *bn_res = NULL;
    BN_MONT_CTX *mont = NULL;
    if (!ctx) goto cleanup;

    bn_a = BN_bin2bn(a, a_len, NULL);
    bn_mod = BN_bin2bn(mod, mod_len, NULL);
    bn_res = BN_new();
    if (!bn_a || !bn_mod || !bn_res) goto cleanup;

    if (BN_is_odd(bn_mod) && !BN_is_one(bn_mod)) {
        /* Use AWS-LC constant-time blinded modular inversion for odd moduli */
        mont = BN_MONT_CTX_new_for_modulus(bn_mod, ctx);
        if (!mont) { rc = -2; goto cleanup; }
        int no_inverse = 0;
        if (BN_mod_inverse_blinded(bn_res, &no_inverse, bn_a, mont, ctx) != 1 || no_inverse) {
            rc = -2;
            goto cleanup;
        }
    } else {
        if (!BN_mod_inverse(bn_res, bn_a, bn_mod, ctx)) {
            rc = -2;
            goto cleanup;
        }
    }

    if (BN_bn2bin_padded(out, out_len, bn_res) != 1) {
        rc = -3;
        goto cleanup;
    }
    rc = 0;

cleanup:
    BN_MONT_CTX_free(mont);
    BN_clear_free(bn_a);
    BN_clear_free(bn_mod);
    BN_clear_free(bn_res);
    BN_CTX_free(ctx);
    return rc;
}

static int decode_p256_point(
    const EC_GROUP *grp,
    const uint8_t *pt33,
    EC_POINT *out,
    BN_CTX *ctx) {
    if (pt33[0] == 0x00) {
        return EC_POINT_set_to_infinity(grp, out) == 1 ? 0 : -1;
    }
    if (pt33[0] != 0x02 && pt33[0] != 0x03) {
        return -2;
    }
    if (EC_POINT_oct2point(grp, out, pt33, 33, ctx) != 1) {
        return -3;
    }
    if (EC_POINT_is_on_curve(grp, out, ctx) != 1) {
        return -4;
    }
    return 0;
}

static int encode_p256_point(
    const EC_GROUP *grp,
    const EC_POINT *pt,
    uint8_t *out33,
    BN_CTX *ctx) {
    if (EC_POINT_is_at_infinity(grp, pt) == 1) {
        memset(out33, 0, 33);
        return 0;
    }
    size_t n = EC_POINT_point2oct(
        grp, pt, POINT_CONVERSION_COMPRESSED, out33, 33, ctx);
    return (n == 33) ? 0 : -1;
}

int pmset_ct_p256_scalar_mul(
    const uint8_t *scalar32,
    const uint8_t *pt33,
    uint8_t *out33) {
    ensure_awslc_init();
    int rc = -1;
    BN_CTX *ctx = BN_CTX_new();
    EC_GROUP *grp = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    BIGNUM *bn_k = BN_bin2bn(scalar32, 32, NULL);
    EC_POINT *P = NULL, *R = NULL;
    if (!ctx || !grp || !bn_k) goto cleanup;

    R = EC_POINT_new(grp);
    if (!R) goto cleanup;

    if (pt33 == NULL) {
        if (EC_POINT_mul(grp, R, bn_k, NULL, NULL, ctx) != 1) { rc = -2; goto cleanup; }
    } else {
        P = EC_POINT_new(grp);
        if (!P) goto cleanup;
        if (decode_p256_point(grp, pt33, P, ctx) != 0) { rc = -3; goto cleanup; }
        if (EC_POINT_mul(grp, R, NULL, P, bn_k, ctx) != 1) { rc = -4; goto cleanup; }
    }
    rc = encode_p256_point(grp, R, out33, ctx);

cleanup:
    EC_POINT_clear_free(P);
    EC_POINT_clear_free(R);
    BN_clear_free(bn_k);
    EC_GROUP_free(grp);
    BN_CTX_free(ctx);
    return rc;
}

int pmset_ct_p256_point_add(
    const uint8_t *p1_33,
    const uint8_t *p2_33,
    uint8_t *out33) {
    ensure_awslc_init();
    int rc = -1;
    BN_CTX *ctx = BN_CTX_new();
    EC_GROUP *grp = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    EC_POINT *P1 = NULL, *P2 = NULL, *R = NULL;
    if (!ctx || !grp) goto cleanup;

    P1 = EC_POINT_new(grp);
    P2 = EC_POINT_new(grp);
    R = EC_POINT_new(grp);
    if (!P1 || !P2 || !R) goto cleanup;

    if (decode_p256_point(grp, p1_33, P1, ctx) != 0) { rc = -2; goto cleanup; }
    if (decode_p256_point(grp, p2_33, P2, ctx) != 0) { rc = -3; goto cleanup; }
    if (EC_POINT_add(grp, R, P1, P2, ctx) != 1) { rc = -4; goto cleanup; }
    rc = encode_p256_point(grp, R, out33, ctx);

cleanup:
    EC_POINT_clear_free(P1);
    EC_POINT_clear_free(P2);
    EC_POINT_clear_free(R);
    EC_GROUP_free(grp);
    BN_CTX_free(ctx);
    return rc;
}

int pmset_ct_p256_point_neg(const uint8_t *p33, uint8_t *out33) {
    ensure_awslc_init();
    int rc = -1;
    BN_CTX *ctx = BN_CTX_new();
    EC_GROUP *grp = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    EC_POINT *P = NULL;
    if (!ctx || !grp) goto cleanup;

    P = EC_POINT_new(grp);
    if (!P) goto cleanup;
    if (decode_p256_point(grp, p33, P, ctx) != 0) { rc = -2; goto cleanup; }
    if (EC_POINT_invert(grp, P, ctx) != 1) { rc = -3; goto cleanup; }
    rc = encode_p256_point(grp, P, out33, ctx);

cleanup:
    EC_POINT_clear_free(P);
    EC_GROUP_free(grp);
    BN_CTX_free(ctx);
    return rc;
}

int pmset_ct_p256_ot_choose(
    const uint8_t *A33,
    const uint8_t *b32,
    uint8_t choice,
    uint8_t *B_out33,
    uint8_t *shared_out33) {
    ensure_awslc_init();
    int rc = -1;
    BN_CTX *ctx = BN_CTX_new();
    EC_GROUP *grp = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    BIGNUM *bn_b = BN_bin2bn(b32, 32, NULL);
    EC_POINT *A = NULL, *bG = NULL, *A_plus_bG = NULL, *bA = NULL;
    uint8_t ser0[33], ser1[33];

    if (!ctx || !grp || !bn_b) goto cleanup;

    A = EC_POINT_new(grp);
    bG = EC_POINT_new(grp);
    A_plus_bG = EC_POINT_new(grp);
    bA = EC_POINT_new(grp);
    if (!A || !bG || !A_plus_bG || !bA) goto cleanup;

    if (decode_p256_point(grp, A33, A, ctx) != 0) { rc = -2; goto cleanup; }
    if (EC_POINT_mul(grp, bG, bn_b, NULL, NULL, ctx) != 1) { rc = -3; goto cleanup; }
    if (EC_POINT_add(grp, A_plus_bG, A, bG, ctx) != 1) { rc = -4; goto cleanup; }
    if (EC_POINT_mul(grp, bA, NULL, A, bn_b, ctx) != 1) { rc = -5; goto cleanup; }

    if (encode_p256_point(grp, bG, ser0, ctx) != 0) { rc = -6; goto cleanup; }
    if (encode_p256_point(grp, A_plus_bG, ser1, ctx) != 0) { rc = -7; goto cleanup; }
    if (encode_p256_point(grp, bA, shared_out33, ctx) != 0) { rc = -8; goto cleanup; }

    pmset_ct_select_bytes(B_out33, ser0, ser1, 33, choice);
    rc = 0;

cleanup:
    OPENSSL_cleanse(ser0, sizeof(ser0));
    OPENSSL_cleanse(ser1, sizeof(ser1));
    EC_POINT_clear_free(A);
    EC_POINT_clear_free(bG);
    EC_POINT_clear_free(A_plus_bG);
    EC_POINT_clear_free(bA);
    BN_clear_free(bn_b);
    EC_GROUP_free(grp);
    BN_CTX_free(ctx);
    return rc;
}

int pmset_ct_p256_elgamal_is_zero(
    const uint8_t *sk32,
    const uint8_t *c1_33,
    const uint8_t *c2_33) {
    uint8_t sk_c1[33];
    if (pmset_ct_p256_scalar_mul(sk32, c1_33, sk_c1) != 0) {
        OPENSSL_cleanse(sk_c1, sizeof(sk_c1));
        return -1;
    }
    int is_zero = pmset_ct_memcmp(sk_c1, c2_33, 33);
    OPENSSL_cleanse(sk_c1, sizeof(sk_c1));
    return is_zero;
}

int pmset_ct_p256_elgamal_any_zero(
    const uint8_t *sk32,
    const uint8_t *c1s_flat,
    const uint8_t *c2s_flat,
    size_t count) {
    ensure_awslc_init();
    int rc = 0;
    uint8_t found = 0;
    BN_CTX *ctx = BN_CTX_new();
    EC_GROUP *grp = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    BIGNUM *bn_sk = BN_bin2bn(sk32, 32, NULL);
    EC_POINT *C1 = NULL, *R = NULL;
    uint8_t sk_c1[33];

    if (!ctx || !grp || !bn_sk) { rc = -1; goto cleanup; }

    C1 = EC_POINT_new(grp);
    R = EC_POINT_new(grp);
    if (!C1 || !R) { rc = -1; goto cleanup; }

    for (size_t i = 0; i < count; i++) {
        const uint8_t *c1 = c1s_flat + (i * 33);
        const uint8_t *c2 = c2s_flat + (i * 33);
        if (decode_p256_point(grp, c1, C1, ctx) != 0) { rc = -2; goto cleanup; }
        if (EC_POINT_mul(grp, R, NULL, C1, bn_sk, ctx) != 1) { rc = -3; goto cleanup; }
        if (encode_p256_point(grp, R, sk_c1, ctx) != 0) { rc = -4; goto cleanup; }
        found |= (uint8_t)pmset_ct_memcmp(sk_c1, c2, 33);
    }
    rc = (int)(found & 1u);

cleanup:
    OPENSSL_cleanse(sk_c1, sizeof(sk_c1));
    EC_POINT_clear_free(C1);
    EC_POINT_clear_free(R);
    BN_clear_free(bn_sk);
    EC_GROUP_free(grp);
    BN_CTX_free(ctx);
    return rc;
}
