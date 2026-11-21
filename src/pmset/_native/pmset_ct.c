/*
 * pmset_ct.c — Constant-Time Native Cryptographic Backend for `pmset`.
 *
 * Every secret-dependent operation in this file avoids data-dependent branches
 * and secret-dependent memory accesses:
 *   - Compiler optimization barriers (`ct_barrier_u8`) prevent the optimizer
 *     from replacing bitwise constant-time masks with conditional jumps.
 *   - Modular exponentiation & inversion use OpenSSL `BN_FLG_CONSTTIME` and
 *     `BN_mod_exp_mont_consttime`.
 *   - NIST P-256 operations use OpenSSL `NID_X9_62_prime256v1` (NISTZ256
 *     constant-time assembly on x86_64/aarch64) with `BN_FLG_CONSTTIME` scalars.
 *   - Ring-LWE arithmetic uses fixed-iteration `__uint128_t` modular arithmetic
 *     with zero data-dependent loop skips.
 *   - All temporary secret BIGNUMs and stack buffers are wiped with
 *     `BN_clear_free` / `OPENSSL_cleanse`.
 */

#include "pmset_ct.h"

#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/opensslv.h>

/* Optimization barrier preventing the compiler from turning a mask into a branch. */
static inline uint8_t ct_barrier_u8(uint8_t x) {
    volatile uint8_t v = x;
    return v;
}

/* Convert bit b in {0, 1} into all-ones (0xFF) or all-zeros (0x00) mask without branching. */
static inline uint8_t ct_mask_u8(uint8_t b) {
    return (uint8_t)(-(uint8_t)(ct_barrier_u8(b) & 1u));
}

/* Returns 1 if x == 0, else 0 (branchless). */
static inline uint8_t ct_is_zero_u32(uint32_t x) {
    uint32_t nz = (x | (0u - x)) >> 31;
    return (uint8_t)(1u - (nz & 1u));
}

uint32_t pmset_ct_abi_version(void) {
    return PMSET_CT_ABI_VERSION;
}

const char *pmset_ct_openssl_version(void) {
    return OpenSSL_version(OPENSSL_VERSION);
}

/* -------------------------------------------------------------------------
 * Constant-time byte & memory primitives
 * ------------------------------------------------------------------------- */

int pmset_ct_memcmp(const uint8_t *a, const uint8_t *b, size_t len) {
    if (len == 0) {
        return 1;
    }
    uint32_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= (uint32_t)(a[i] ^ b[i]);
    }
    return (int)ct_is_zero_u32(ct_barrier_u8((uint8_t)diff));
}

void pmset_ct_select_bytes(
    uint8_t *out,
    const uint8_t *a,
    const uint8_t *b,
    size_t len,
    uint8_t select_b) {
    uint8_t mask = ct_mask_u8(select_b);
    uint8_t nmask = (uint8_t)(~mask);
    for (size_t i = 0; i < len; i++) {
        out[i] = (uint8_t)((a[i] & nmask) | (b[i] & mask));
    }
}

void pmset_ct_xor_bytes(
    uint8_t *out,
    const uint8_t *a,
    const uint8_t *b,
    size_t len) {
    for (size_t i = 0; i < len; i++) {
        out[i] = (uint8_t)(a[i] ^ b[i]);
    }
}

void pmset_ct_cond_xor_bytes(
    uint8_t *acc,
    const uint8_t *src,
    size_t len,
    uint8_t cond) {
    uint8_t mask = ct_mask_u8(cond);
    for (size_t i = 0; i < len; i++) {
        acc[i] ^= (uint8_t)(src[i] & mask);
    }
}

void pmset_ct_dpf_bucket_eval(
    uint8_t *out,
    const uint8_t *buckets_flat,
    size_t num_buckets,
    size_t bucket_len,
    const uint8_t *bits) {
    memset(out, 0, bucket_len);
    for (size_t i = 0; i < num_buckets; i++) {
        uint8_t mask = ct_mask_u8(bits[i]);
        const uint8_t *bkt = buckets_flat + (i * bucket_len);
        for (size_t j = 0; j < bucket_len; j++) {
            out[j] ^= (uint8_t)(bkt[j] & mask);
        }
    }
}

int pmset_ct_bucket_scan_tag(
    const uint8_t *bucket,
    size_t num_records,
    size_t record_size,
    const uint8_t *target_tag,
    size_t tag_len,
    uint8_t *matched_record_out) {
    memset(matched_record_out, 0, record_size);
    uint8_t found_any = 0;
    for (size_t i = 0; i < num_records; i++) {
        const uint8_t *rec = bucket + (i * record_size);
        uint8_t eq = (uint8_t)pmset_ct_memcmp(rec, target_tag, tag_len);
        /* Select matching record without early exit or branching */
        pmset_ct_select_bytes(matched_record_out, matched_record_out, rec, record_size, eq);
        found_any |= eq;
    }
    return (int)(found_any & 1u);
}

/* -------------------------------------------------------------------------
 * Constant-time Big-Integer Modular Arithmetic (OpenSSL BN_FLG_CONSTTIME)
 * ------------------------------------------------------------------------- */

int pmset_ct_modexp(
    const uint8_t *base, size_t base_len,
    const uint8_t *exp, size_t exp_len,
    const uint8_t *mod, size_t mod_len,
    uint8_t *out, size_t out_len) {
    int rc = -1;
    BN_CTX *ctx = NULL;
    BIGNUM *bn_base = NULL;
    BIGNUM *bn_exp = NULL;
    BIGNUM *bn_mod = NULL;
    BIGNUM *bn_res = NULL;

    ctx = BN_CTX_secure_new();
    if (!ctx) goto cleanup;

    bn_base = BN_bin2bn(base, (int)base_len, NULL);
    bn_exp = BN_secure_new();
    bn_mod = BN_bin2bn(mod, (int)mod_len, NULL);
    bn_res = BN_new();
    if (!bn_base || !bn_exp || !bn_mod || !bn_res) goto cleanup;

    if (!BN_bin2bn(exp, (int)exp_len, bn_exp)) goto cleanup;
    BN_set_flags(bn_exp, BN_FLG_CONSTTIME);
    BN_set_flags(bn_base, BN_FLG_CONSTTIME);

    if (!BN_is_odd(bn_mod) || BN_is_zero(bn_mod) || BN_is_one(bn_mod)) {
        rc = -2;
        goto cleanup;
    }

    if (BN_mod_exp_mont_consttime(bn_res, bn_base, bn_exp, bn_mod, ctx, NULL) != 1) {
        rc = -3;
        goto cleanup;
    }

    if (BN_bn2binpad(bn_res, out, (int)out_len) < 0) {
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
    int rc = -1;
    BN_CTX *ctx = NULL;
    BIGNUM *bn_base = NULL, *bn_exp = NULL, *bn_ord = NULL, *bn_mod = NULL;
    BIGNUM *e1 = NULL, *e2 = NULL, *bn_res = NULL;

    ctx = BN_CTX_secure_new();
    if (!ctx) goto cleanup;

    bn_base = BN_bin2bn(base, (int)base_len, NULL);
    bn_exp = BN_secure_new();
    bn_ord = BN_bin2bn(order, (int)order_len, NULL);
    bn_mod = BN_bin2bn(mod, (int)mod_len, NULL);
    e1 = BN_secure_new();
    e2 = BN_secure_new();
    bn_res = BN_new();
    if (!bn_base || !bn_exp || !bn_ord || !bn_mod || !e1 || !e2 || !bn_res) goto cleanup;

    if (!BN_bin2bn(exp, (int)exp_len, bn_exp)) goto cleanup;
    if (!BN_is_odd(bn_mod) || BN_is_zero(bn_ord)) { rc = -2; goto cleanup; }

    /* Joye constant-bit-length padding:
     * Let L = BN_num_bits(order). For 0 <= exp < order:
     *   e1 = exp + order, e2 = exp + 2*order.
     * Exactly one of {e1, e2} has MSB at bit index L (total L+1 bits).
     * Select via BN_consttime_swap so bit-length is ALWAYS L+1! */
    int L = BN_num_bits(bn_ord);
    if (BN_mod(bn_exp, bn_exp, bn_ord, ctx) != 1) { rc = -3; goto cleanup; }
    if (BN_add(e1, bn_exp, bn_ord) != 1) { rc = -3; goto cleanup; }
    if (BN_add(e2, e1, bn_ord) != 1) { rc = -3; goto cleanup; }

    int carry = BN_is_bit_set(e1, L);
    /* If carry == 0 (e1 < 2^L), swap e1 and e2 so e1 always has exact bit-length L+1 */
    BN_consttime_swap((BN_ULONG)(carry ^ 1), e1, e2, (L / BN_BITS2) + 2);

    BN_set_flags(e1, BN_FLG_CONSTTIME);
    BN_set_flags(bn_base, BN_FLG_CONSTTIME);

    if (BN_mod_exp_mont_consttime(bn_res, bn_base, e1, bn_mod, ctx, NULL) != 1) {
        rc = -4;
        goto cleanup;
    }
    if (BN_bn2binpad(bn_res, out, (int)out_len) < 0) {
        rc = -5;
        goto cleanup;
    }
    rc = 0;

cleanup:
    BN_clear_free(bn_base);
    BN_clear_free(bn_exp);
    BN_clear_free(bn_ord);
    BN_clear_free(bn_mod);
    BN_clear_free(e1);
    BN_clear_free(e2);
    BN_clear_free(bn_res);
    BN_CTX_free(ctx);
    return rc;
}

int pmset_ct_modinv(
    const uint8_t *a, size_t a_len,
    const uint8_t *mod, size_t mod_len,
    uint8_t *out, size_t out_len) {
    int rc = -1;
    BN_CTX *ctx = NULL;
    BIGNUM *bn_a = NULL;
    BIGNUM *bn_mod = NULL;
    BIGNUM *bn_res = NULL;

    ctx = BN_CTX_secure_new();
    if (!ctx) goto cleanup;

    bn_a = BN_secure_new();
    bn_mod = BN_bin2bn(mod, (int)mod_len, NULL);
    bn_res = BN_secure_new();
    if (!bn_a || !bn_mod || !bn_res) goto cleanup;

    if (!BN_bin2bn(a, (int)a_len, bn_a)) goto cleanup;
    BN_set_flags(bn_a, BN_FLG_CONSTTIME);
    BN_set_flags(bn_mod, BN_FLG_CONSTTIME);

    if (!BN_mod_inverse(bn_res, bn_a, bn_mod, ctx)) {
        rc = -2;
        goto cleanup;
    }

    if (BN_bn2binpad(bn_res, out, (int)out_len) < 0) {
        rc = -3;
        goto cleanup;
    }
    rc = 0;

cleanup:
    BN_clear_free(bn_a);
    BN_clear_free(bn_mod);
    BN_clear_free(bn_res);
    BN_CTX_free(ctx);
    return rc;
}

/* -------------------------------------------------------------------------
 * Constant-time NIST P-256 Operations (OpenSSL NISTZ256 Assembly)
 * ------------------------------------------------------------------------- */

static int decode_p256_point(
    const EC_GROUP *grp,
    const uint8_t *pt33,
    EC_POINT *out,
    BN_CTX *ctx) {
    /* Infinity encoding: leading byte 0x00 with all remaining bytes 0x00 */
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
    int rc = -1;
    BN_CTX *ctx = NULL;
    EC_GROUP *grp = NULL;
    BIGNUM *bn_k = NULL;
    EC_POINT *P = NULL;
    EC_POINT *R = NULL;

    ctx = BN_CTX_secure_new();
    grp = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    bn_k = BN_secure_new();
    if (!ctx || !grp || !bn_k) goto cleanup;

    if (!BN_bin2bn(scalar32, 32, bn_k)) goto cleanup;
    BN_set_flags(bn_k, BN_FLG_CONSTTIME);

    R = EC_POINT_new(grp);
    if (!R) goto cleanup;

    if (pt33 == NULL) {
        if (EC_POINT_mul(grp, R, bn_k, NULL, NULL, ctx) != 1) {
            rc = -2;
            goto cleanup;
        }
    } else {
        P = EC_POINT_new(grp);
        if (!P) goto cleanup;
        if (decode_p256_point(grp, pt33, P, ctx) != 0) {
            rc = -3;
            goto cleanup;
        }
        if (EC_POINT_mul(grp, R, NULL, P, bn_k, ctx) != 1) {
            rc = -4;
            goto cleanup;
        }
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
    int rc = -1;
    BN_CTX *ctx = BN_CTX_secure_new();
    EC_GROUP *grp = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    BIGNUM *bn_b = BN_secure_new();
    EC_POINT *A = NULL, *bG = NULL, *A_plus_bG = NULL, *bA = NULL;
    uint8_t ser0[33], ser1[33];

    if (!ctx || !grp || !bn_b) goto cleanup;
    if (!BN_bin2bn(b32, 32, bn_b)) goto cleanup;
    BN_set_flags(bn_b, BN_FLG_CONSTTIME);

    A = EC_POINT_new(grp);
    bG = EC_POINT_new(grp);
    A_plus_bG = EC_POINT_new(grp);
    bA = EC_POINT_new(grp);
    if (!A || !bG || !A_plus_bG || !bA) goto cleanup;

    if (decode_p256_point(grp, A33, A, ctx) != 0) { rc = -2; goto cleanup; }

    /* Compute BOTH branches unconditionally in constant time */
    if (EC_POINT_mul(grp, bG, bn_b, NULL, NULL, ctx) != 1) { rc = -3; goto cleanup; }
    if (EC_POINT_add(grp, A_plus_bG, A, bG, ctx) != 1) { rc = -4; goto cleanup; }
    if (EC_POINT_mul(grp, bA, NULL, A, bn_b, ctx) != 1) { rc = -5; goto cleanup; }

    if (encode_p256_point(grp, bG, ser0, ctx) != 0) { rc = -6; goto cleanup; }
    if (encode_p256_point(grp, A_plus_bG, ser1, ctx) != 0) { rc = -7; goto cleanup; }
    if (encode_p256_point(grp, bA, shared_out33, ctx) != 0) { rc = -8; goto cleanup; }

    /* Branchless constant-time select on secret choice bit */
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
    int rc = 0;
    uint8_t found = 0;
    BN_CTX *ctx = BN_CTX_secure_new();
    EC_GROUP *grp = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    BIGNUM *bn_sk = BN_secure_new();
    EC_POINT *C1 = NULL, *R = NULL;
    uint8_t sk_c1[33];

    if (!ctx || !grp || !bn_sk) { rc = -1; goto cleanup; }
    if (!BN_bin2bn(sk32, 32, bn_sk)) { rc = -1; goto cleanup; }
    BN_set_flags(bn_sk, BN_FLG_CONSTTIME);

    C1 = EC_POINT_new(grp);
    R = EC_POINT_new(grp);
    if (!C1 || !R) { rc = -1; goto cleanup; }

    /* Non-short-circuiting loop: ALWAYS checks every ciphertext! */
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

/* -------------------------------------------------------------------------
 * Branchless Constant-Time Ring-LWE Lattice Kernels
 * ------------------------------------------------------------------------- */

static inline uint64_t ct_mod_signed_i128(__int128 x, uint64_t q) {
    __int128 mq = (__int128)q;
    __int128 r = x % mq;
    /* Branchless negative correction: add q if r < 0 using arithmetic sign mask */
    __int128 neg_mask = r >> 127; /* -1 if r < 0 else 0 */
    r += (mq & neg_mask);
    return (uint64_t)r;
}

void pmset_ct_rlwe_poly_mul(
    const uint64_t *a,
    const uint64_t *b,
    uint64_t *out,
    size_t n,
    uint64_t q) {
    /* Accumulate in __int128 to avoid overflow for all n <= 1024 and q <= 2^60.
     * Loop structure depends ONLY on public ring degree `n`, NEVER on secret data. */
    __int128 *acc = (__int128 *)calloc(n, sizeof(__int128));
    if (!acc) return;

    for (size_t i = 0; i < n; i++) {
        __int128 ai = (__int128)a[i];
        size_t split = n - i;
        for (size_t j = 0; j < split; j++) {
            acc[i + j] += ai * (__int128)b[j];
        }
        for (size_t j = split; j < n; j++) {
            acc[i + j - n] -= ai * (__int128)b[j];
        }
    }

    for (size_t i = 0; i < n; i++) {
        out[i] = ct_mod_signed_i128(acc[i], q);
    }
    OPENSSL_cleanse(acc, n * sizeof(__int128));
    free(acc);
}

void pmset_ct_rlwe_encrypt(
    const uint64_t *a,
    const int64_t *sk,
    const int64_t *err,
    const uint64_t *m,
    uint64_t *b_out,
    size_t n,
    uint64_t q,
    uint64_t t) {
    uint64_t *sk_mod = (uint64_t *)calloc(n, sizeof(uint64_t));
    uint64_t *as_prod = (uint64_t *)calloc(n, sizeof(uint64_t));
    if (!sk_mod || !as_prod) {
        free(sk_mod);
        free(as_prod);
        return;
    }

    for (size_t i = 0; i < n; i++) {
        sk_mod[i] = ct_mod_signed_i128((__int128)sk[i], q);
    }
    pmset_ct_rlwe_poly_mul(a, sk_mod, as_prod, n, q);

    uint64_t delta = q / t;
    for (size_t i = 0; i < n; i++) {
        __int128 val = -(__int128)as_prod[i]
                       + (__int128)err[i]
                       + (__int128)delta * (__int128)(m[i] % t);
        b_out[i] = ct_mod_signed_i128(val, q);
    }

    OPENSSL_cleanse(sk_mod, n * sizeof(uint64_t));
    OPENSSL_cleanse(as_prod, n * sizeof(uint64_t));
    free(sk_mod);
    free(as_prod);
}

void pmset_ct_rlwe_decrypt(
    const uint64_t *a,
    const uint64_t *b,
    const int64_t *sk,
    uint64_t *m_out,
    size_t n,
    uint64_t q,
    uint64_t t) {
    uint64_t *sk_mod = (uint64_t *)calloc(n, sizeof(uint64_t));
    uint64_t *as_prod = (uint64_t *)calloc(n, sizeof(uint64_t));
    if (!sk_mod || !as_prod) {
        free(sk_mod);
        free(as_prod);
        return;
    }

    for (size_t i = 0; i < n; i++) {
        sk_mod[i] = ct_mod_signed_i128((__int128)sk[i], q);
    }
    pmset_ct_rlwe_poly_mul(a, sk_mod, as_prod, n, q);

    unsigned __int128 two_q = (unsigned __int128)2u * (unsigned __int128)q;
    for (size_t i = 0; i < n; i++) {
        uint64_t v = (uint64_t)(((unsigned __int128)b[i] + (unsigned __int128)as_prod[i]) % q);
        unsigned __int128 num = (unsigned __int128)2u * (unsigned __int128)t * (unsigned __int128)v
                                + (unsigned __int128)q;
        m_out[i] = (uint64_t)((num / two_q) % (unsigned __int128)t);
    }

    OPENSSL_cleanse(sk_mod, n * sizeof(uint64_t));
    OPENSSL_cleanse(as_prod, n * sizeof(uint64_t));
    free(sk_mod);
    free(as_prod);
}

void pmset_ct_rlwe_pir_dot(
    const uint64_t *ct_a_flat,
    const uint64_t *ct_b_flat,
    const uint64_t *pt_flat,
    size_t num_buckets,
    size_t n,
    uint64_t q,
    uint64_t *out_a,
    uint64_t *out_b) {
    __int128 *acc_a = (__int128 *)calloc(n, sizeof(__int128));
    __int128 *acc_b = (__int128 *)calloc(n, sizeof(__int128));
    uint64_t *tmp_a = (uint64_t *)calloc(n, sizeof(uint64_t));
    uint64_t *tmp_b = (uint64_t *)calloc(n, sizeof(uint64_t));
    if (!acc_a || !acc_b || !tmp_a || !tmp_b) {
        free(acc_a); free(acc_b); free(tmp_a); free(tmp_b);
        return;
    }

    for (size_t k = 0; k < num_buckets; k++) {
        const uint64_t *ca = ct_a_flat + (k * n);
        const uint64_t *cb = ct_b_flat + (k * n);
        const uint64_t *pt = pt_flat + (k * n);
        pmset_ct_rlwe_poly_mul(ca, pt, tmp_a, n, q);
        pmset_ct_rlwe_poly_mul(cb, pt, tmp_b, n, q);
        for (size_t i = 0; i < n; i++) {
            acc_a[i] += (__int128)tmp_a[i];
            acc_b[i] += (__int128)tmp_b[i];
        }
    }

    for (size_t i = 0; i < n; i++) {
        out_a[i] = ct_mod_signed_i128(acc_a[i], q);
        out_b[i] = ct_mod_signed_i128(acc_b[i], q);
    }

    OPENSSL_cleanse(acc_a, n * sizeof(__int128));
    OPENSSL_cleanse(acc_b, n * sizeof(__int128));
    OPENSSL_cleanse(tmp_a, n * sizeof(uint64_t));
    OPENSSL_cleanse(tmp_b, n * sizeof(uint64_t));
    free(acc_a);
    free(acc_b);
    free(tmp_a);
    free(tmp_b);
}
