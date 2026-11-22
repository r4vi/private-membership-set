/*
 * pmset_ct.h — Pluggable Constant-Time Native Cryptographic ABI for `pmset`.
 *
 * Any native backend (OpenSSL, AWS-LC / s2n-bignum, BoringSSL, Rust FFI, etc.)
 * implementing these exported symbols plugs directly into `pmset.native`.
 */

#ifndef PMSET_CT_H
#define PMSET_CT_H

#include <stddef.h>
#include <stdint.h>

#define PMSET_CT_ABI_VERSION 2u

#if defined(__GNUC__) || defined(__clang__)
#define PMSET_EXPORT __attribute__((visibility("default")))
#else
#define PMSET_EXPORT
#endif

#ifdef __cplusplus
extern "C" {
#endif

PMSET_EXPORT uint32_t pmset_ct_abi_version(void);
PMSET_EXPORT const char *pmset_ct_provider_name(void);
PMSET_EXPORT const char *pmset_ct_provider_version(void);
/* Backward-compatible alias for ABI v1 callers */
PMSET_EXPORT const char *pmset_ct_openssl_version(void);

/* Internal constant-time memory wipe helper */
void pmset_ct_cleanse(void *ptr, size_t len);

/* --- Constant-time byte & memory primitives (provider-independent) --- */

PMSET_EXPORT int pmset_ct_memcmp(const uint8_t *a, const uint8_t *b, size_t len);

PMSET_EXPORT void pmset_ct_select_bytes(
    uint8_t *out,
    const uint8_t *a,
    const uint8_t *b,
    size_t len,
    uint8_t select_b);

PMSET_EXPORT void pmset_ct_xor_bytes(
    uint8_t *out,
    const uint8_t *a,
    const uint8_t *b,
    size_t len);

PMSET_EXPORT void pmset_ct_cond_xor_bytes(
    uint8_t *acc,
    const uint8_t *src,
    size_t len,
    uint8_t cond);

PMSET_EXPORT void pmset_ct_dpf_bucket_eval(
    uint8_t *out,
    const uint8_t *buckets_flat,
    size_t num_buckets,
    size_t bucket_len,
    const uint8_t *bits);

PMSET_EXPORT int pmset_ct_bucket_scan_tag(
    const uint8_t *bucket,
    size_t num_records,
    size_t record_size,
    const uint8_t *target_tag,
    size_t tag_len,
    uint8_t *matched_record_out);

/* --- Constant-time Big-Integer Modular Arithmetic (provider-specific) --- */

PMSET_EXPORT int pmset_ct_modexp(
    const uint8_t *base, size_t base_len,
    const uint8_t *exp, size_t exp_len,
    const uint8_t *mod, size_t mod_len,
    uint8_t *out, size_t out_len);

PMSET_EXPORT int pmset_ct_modexp_order(
    const uint8_t *base, size_t base_len,
    const uint8_t *exp, size_t exp_len,
    const uint8_t *order, size_t order_len,
    const uint8_t *mod, size_t mod_len,
    uint8_t *out, size_t out_len);

PMSET_EXPORT int pmset_ct_modinv(
    const uint8_t *a, size_t a_len,
    const uint8_t *mod, size_t mod_len,
    uint8_t *out, size_t out_len);

/* --- Constant-time NIST P-256 Elliptic Curve Operations (provider-specific) --- */

PMSET_EXPORT int pmset_ct_p256_scalar_mul(
    const uint8_t *scalar32,
    const uint8_t *pt33,
    uint8_t *out33);

PMSET_EXPORT int pmset_ct_p256_point_add(
    const uint8_t *p1_33,
    const uint8_t *p2_33,
    uint8_t *out33);

PMSET_EXPORT int pmset_ct_p256_point_neg(
    const uint8_t *p33,
    uint8_t *out33);

PMSET_EXPORT int pmset_ct_p256_ot_choose(
    const uint8_t *A33,
    const uint8_t *b32,
    uint8_t choice,
    uint8_t *B_out33,
    uint8_t *shared_out33);

PMSET_EXPORT int pmset_ct_p256_elgamal_is_zero(
    const uint8_t *sk32,
    const uint8_t *c1_33,
    const uint8_t *c2_33);

PMSET_EXPORT int pmset_ct_p256_elgamal_any_zero(
    const uint8_t *sk32,
    const uint8_t *c1s_flat,
    const uint8_t *c2s_flat,
    size_t count);

/* --- Branchless Constant-Time Ring-LWE Lattice Kernels (provider-independent) --- */

PMSET_EXPORT void pmset_ct_rlwe_poly_mul(
    const uint64_t *a,
    const uint64_t *b,
    uint64_t *out,
    size_t n,
    uint64_t q);

PMSET_EXPORT void pmset_ct_rlwe_encrypt(
    const uint64_t *a,
    const int64_t *sk,
    const int64_t *err,
    const uint64_t *m,
    uint64_t *b_out,
    size_t n,
    uint64_t q,
    uint64_t t);

PMSET_EXPORT void pmset_ct_rlwe_decrypt(
    const uint64_t *a,
    const uint64_t *b,
    const int64_t *sk,
    uint64_t *m_out,
    size_t n,
    uint64_t q,
    uint64_t t);

PMSET_EXPORT void pmset_ct_rlwe_pir_dot(
    const uint64_t *ct_a_flat,
    const uint64_t *ct_b_flat,
    const uint64_t *pt_flat,
    size_t num_buckets,
    size_t n,
    uint64_t q,
    uint64_t *out_a,
    uint64_t *out_b);

#ifdef __cplusplus
}
#endif

#endif /* PMSET_CT_H */
