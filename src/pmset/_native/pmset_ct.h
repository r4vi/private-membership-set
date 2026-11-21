/*
 * pmset_ct.h — Constant-Time Native Cryptographic Backend for `pmset`.
 *
 * Combines:
 *   - OpenSSL libcrypto constant-time BIGNUM (`BN_FLG_CONSTTIME`,
 *     `BN_mod_exp_mont_consttime`) and NIST P-256 assembly (`NID_X9_62_prime256v1`)
 *   - Branchless fixed-width C11 kernels for Ring-LWE polynomial arithmetic,
 *     BGI15 DPF XOR evaluation, Chou-Orlandi OT choice masking, and full-scan
 *     bucket tag lookup.
 *   - Secure memory cleansing (`OPENSSL_cleanse`, `BN_clear_free`) for all
 *     transient secret buffers.
 */

#ifndef PMSET_CT_H
#define PMSET_CT_H

#include <stddef.h>
#include <stdint.h>

#define PMSET_CT_ABI_VERSION 1u

#ifdef __cplusplus
extern "C" {
#endif

uint32_t pmset_ct_abi_version(void);
const char *pmset_ct_openssl_version(void);

/* --- Constant-time byte & memory primitives --- */

/* Returns 1 if a[0..len-1] == b[0..len-1], 0 otherwise (constant time). */
int pmset_ct_memcmp(const uint8_t *a, const uint8_t *b, size_t len);

/* Branchless select: out = select_b ? b : a (select_b in {0, 1}). */
void pmset_ct_select_bytes(
    uint8_t *out,
    const uint8_t *a,
    const uint8_t *b,
    size_t len,
    uint8_t select_b);

/* Constant-time bytewise XOR: out[i] = a[i] ^ b[i]. */
void pmset_ct_xor_bytes(
    uint8_t *out,
    const uint8_t *a,
    const uint8_t *b,
    size_t len);

/* Branchless conditional XOR: if cond==1 then acc ^= src else unchanged. */
void pmset_ct_cond_xor_bytes(
    uint8_t *acc,
    const uint8_t *src,
    size_t len,
    uint8_t cond);

/* Branchless 2-server DPF XOR evaluation over all `num_buckets` buckets. */
void pmset_ct_dpf_bucket_eval(
    uint8_t *out,
    const uint8_t *buckets_flat,
    size_t num_buckets,
    size_t bucket_len,
    const uint8_t *bits);

/* Constant-time full scan of all records in a bucket (zero early return).
 * Copies the matching record into `matched_record_out` via ct_select_bytes.
 * Returns 1 if any record's leading `tag_len` bytes matched `target_tag`, else 0. */
int pmset_ct_bucket_scan_tag(
    const uint8_t *bucket,
    size_t num_records,
    size_t record_size,
    const uint8_t *target_tag,
    size_t tag_len,
    uint8_t *matched_record_out);

/* --- Constant-time Big-Integer Modular Arithmetic (OpenSSL BN_FLG_CONSTTIME) --- */

/* out = base^exp mod mod (big-endian unsigned byte arrays; mod must be odd > 1).
 * Returns 0 on success, negative on error. */
int pmset_ct_modexp(
    const uint8_t *base, size_t base_len,
    const uint8_t *exp, size_t exp_len,
    const uint8_t *mod, size_t mod_len,
    uint8_t *out, size_t out_len);

/* Fixed-bit-length constant-time modexp when subgroup order `order` is known
 * (base^order == 1 mod mod). Pads exp via Joye's trick to exact bit-length
 * bit_len(order) + 1 using BN_consttime_swap so even exp=1 and exp=order-1
 * execute the exact same number of Montgomery rounds. */
int pmset_ct_modexp_order(
    const uint8_t *base, size_t base_len,
    const uint8_t *exp, size_t exp_len,
    const uint8_t *order, size_t order_len,
    const uint8_t *mod, size_t mod_len,
    uint8_t *out, size_t out_len);

/* out = a^(-1) mod mod (big-endian unsigned byte arrays).
 * Returns 0 on success, negative if not invertible or error. */
int pmset_ct_modinv(
    const uint8_t *a, size_t a_len,
    const uint8_t *mod, size_t mod_len,
    uint8_t *out, size_t out_len);

/* --- Constant-time NIST P-256 Elliptic Curve Operations (OpenSSL NISTZ256) --- */

/* out33 = scalar32 * pt33 (if pt33 == NULL, multiplies generator G).
 * Points use 33-byte SEC1 compressed format (or 0x00 + 32 zeros for infinity).
 * Returns 0 on success, negative on invalid point/error. */
int pmset_ct_p256_scalar_mul(
    const uint8_t *scalar32,
    const uint8_t *pt33,
    uint8_t *out33);

/* out33 = p1_33 + p2_33 on NIST P-256. Returns 0 on success. */
int pmset_ct_p256_point_add(
    const uint8_t *p1_33,
    const uint8_t *p2_33,
    uint8_t *out33);

/* out33 = -p33 on NIST P-256. Returns 0 on success. */
int pmset_ct_p256_point_neg(
    const uint8_t *p33,
    uint8_t *out33);

/* Constant-time Chou-Orlandi 1-out-of-2 OT receiver choice:
 * Computes P0 = b*G, P1 = A + b*G, shared = b*A unconditionally, and selects
 * B_out33 = ct_select(P0, P1, choice) with ZERO branches on `choice`. */
int pmset_ct_p256_ot_choose(
    const uint8_t *A33,
    const uint8_t *b32,
    uint8_t choice,
    uint8_t *B_out33,
    uint8_t *shared_out33);

/* Constant-time Exponential ElGamal zero test: returns 1 iff C2 == sk * C1, 0 otherwise, <0 error. */
int pmset_ct_p256_elgamal_is_zero(
    const uint8_t *sk32,
    const uint8_t *c1_33,
    const uint8_t *c2_33);

/* Non-short-circuiting ElGamal zero test across `count` ciphertexts.
 * Always evaluates ALL `count` ciphertexts; returns 1 if any is zero, 0 otherwise, <0 error. */
int pmset_ct_p256_elgamal_any_zero(
    const uint8_t *sk32,
    const uint8_t *c1s_flat,
    const uint8_t *c2s_flat,
    size_t count);

/* --- Branchless Constant-Time Ring-LWE Lattice Kernels --- */

/* Negacyclic polynomial multiplication in Z_q[X]/(X^n + 1) with ZERO secret-dependent branches. */
void pmset_ct_rlwe_poly_mul(
    const uint64_t *a,
    const uint64_t *b,
    uint64_t *out,
    size_t n,
    uint64_t q);

/* Constant-time RLWE encryption: b_out = (-a*sk + err + (q/t)*m) mod q. */
void pmset_ct_rlwe_encrypt(
    const uint64_t *a,
    const int64_t *sk,
    const int64_t *err,
    const uint64_t *m,
    uint64_t *b_out,
    size_t n,
    uint64_t q,
    uint64_t t);

/* Constant-time RLWE decryption: m_out = round(t * ((b + a*sk) mod q) / q) mod t. */
void pmset_ct_rlwe_decrypt(
    const uint64_t *a,
    const uint64_t *b,
    const int64_t *sk,
    uint64_t *m_out,
    size_t n,
    uint64_t q,
    uint64_t t);

/* Constant-time RLWE PIR inner product across `num_buckets` ciphertext-plaintext pairs. */
void pmset_ct_rlwe_pir_dot(
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
