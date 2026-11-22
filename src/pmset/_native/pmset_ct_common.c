/*
 * pmset_ct_common.c — Provider-independent branchless C11 kernels shared by
 * all native backends (OpenSSL, AWS-LC, etc.):
 *   - Constant-time byte comparison, conditional selection, conditional XOR
 *   - Branchless 2-server BGI15 DPF bucket evaluation
 *   - Constant-time full-scan bucket tag lookup
 *   - Branchless Ring-LWE polynomial multiplication, encryption, decryption, PIR dot
 */

#include "pmset_ct.h"

#include <stdlib.h>
#include <string.h>

static inline uint8_t ct_barrier_u8(uint8_t x) {
    volatile uint8_t v = x;
    return v;
}

static inline uint8_t ct_mask_u8(uint8_t b) {
    return (uint8_t)(-(uint8_t)(ct_barrier_u8(b) & 1u));
}

static inline uint8_t ct_is_zero_u32(uint32_t x) {
    uint32_t nz = (x | (0u - x)) >> 31;
    return (uint8_t)(1u - (nz & 1u));
}

void pmset_ct_cleanse(void *ptr, size_t len) {
    if (!ptr || len == 0) {
        return;
    }
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) {
        *p++ = 0;
    }
}

uint32_t pmset_ct_abi_version(void) {
    return PMSET_CT_ABI_VERSION;
}

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
    if (!out || bucket_len == 0) {
        return;
    }
    memset(out, 0, bucket_len);
    if (!buckets_flat || !bits || num_buckets == 0) {
        return;
    }
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
    if (!matched_record_out || record_size == 0 || tag_len > record_size) {
        return -1;
    }
    memset(matched_record_out, 0, record_size);
    if (!bucket || !target_tag || num_records == 0) {
        return 0;
    }
    uint8_t found_any = 0;
    for (size_t i = 0; i < num_records; i++) {
        const uint8_t *rec = bucket + (i * record_size);
        uint8_t eq = (uint8_t)pmset_ct_memcmp(rec, target_tag, tag_len);
        pmset_ct_select_bytes(matched_record_out, matched_record_out, rec, record_size, eq);
        found_any |= eq;
    }
    return (int)(found_any & 1u);
}

/* -------------------------------------------------------------------------
 * Branchless Constant-Time Ring-LWE Lattice Kernels
 * ------------------------------------------------------------------------- */

static inline uint64_t ct_mod_signed_i128(__int128 x, uint64_t q) {
    __int128 mq = (__int128)q;
    __int128 r = x % mq;
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
    pmset_ct_cleanse(acc, n * sizeof(__int128));
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

    pmset_ct_cleanse(sk_mod, n * sizeof(uint64_t));
    pmset_ct_cleanse(as_prod, n * sizeof(uint64_t));
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

    pmset_ct_cleanse(sk_mod, n * sizeof(uint64_t));
    pmset_ct_cleanse(as_prod, n * sizeof(uint64_t));
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

    pmset_ct_cleanse(acc_a, n * sizeof(__int128));
    pmset_ct_cleanse(acc_b, n * sizeof(__int128));
    pmset_ct_cleanse(tmp_a, n * sizeof(uint64_t));
    pmset_ct_cleanse(tmp_b, n * sizeof(uint64_t));
    free(acc_a);
    free(acc_b);
    free(tmp_a);
    free(tmp_b);
}
