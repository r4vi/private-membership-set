/-
  PMSet.OPRF — Machine-Checked Algebraic Proofs for All Three OPRF Primitives:
    1. DH-OPRF over a prime-order subgroup G_q of Z_p*
    2. ECDH-OPRF over a prime-order elliptic curve group (e.g. NIST P-256)
    3. Chaum Blind-RSA OPRF over Z_N*

  Every theorem is kernel-checked with ZERO `sorry` and ZERO custom axioms.
-/

namespace PMSet.OPRF

/-- Abstract multiplicative cyclic group of order `q` (covers both DH G_q and ECDH P-256). -/
structure PrimeOrderGroup (G : Type) where
  q : Nat
  hq_pos : q > 0
  act : Nat → G → G
  act_mul : ∀ a b g, act a (act b g) = act (a * b) g
  act_mod : ∀ a g, act (a % q) g = act a g
  act_one : ∀ g, act 1 g = g

/-- **DH-OPRF & ECDH-OPRF Correctness**:
    If `r * r_inv ≡ 1 (mod q)`, then unblinding the server-evaluated element
    `act r_inv (act k (act r h))` recovers `act k h` identically. -/
theorem group_oprf_unblind_correct {G : Type} (grp : PrimeOrderGroup G)
    (h : G) (k r r_inv : Nat)
    (hinv : (r * r_inv) % grp.q = 1 % grp.q) :
    grp.act r_inv (grp.act k (grp.act r h)) = grp.act k h := by
  rw [grp.act_mul, grp.act_mul]
  have hcomm : r_inv * k * r = k * (r * r_inv) := by
    rw [Nat.mul_comm r_inv k, Nat.mul_assoc, Nat.mul_comm r_inv r]
  rw [hcomm]
  rw [← grp.act_mod (k * (r * r_inv)) h]
  rw [Nat.mul_mod, hinv, ← Nat.mul_mod, Nat.mul_one]
  rw [grp.act_mod]

/-- **DH/ECDH Blinding Indistinguishability (Client Privacy)**:
    In the exponent ring mod `q`, given any two non-zero hash exponents `a1, a2`
    with `a2` invertible mod `q`, and any blinding factor `r1`, there exists `r2`
    producing the exact same blinded exponent `r2 * a2 ≡ r1 * a1 (mod q)`. -/
theorem group_oprf_blinding_private
    (q a1 a2 a2_inv r1 : Nat)
    (hinv : (a2 * a2_inv) % q = 1 % q) :
    ∃ r2 : Nat, (r2 * a2) % q = (r1 * a1) % q := by
  refine ⟨(r1 * a1 * a2_inv) % q, ?_⟩
  rw [Nat.mul_mod, Nat.mod_mod, ← Nat.mul_mod]
  have hassoc : r1 * a1 * a2_inv * a2 = (r1 * a1) * (a2 * a2_inv) := by
    rw [Nat.mul_assoc (r1 * a1) a2_inv a2, Nat.mul_comm a2_inv a2]
  rw [hassoc, Nat.mul_mod, hinv, ← Nat.mul_mod, Nat.mul_one]

/-- Abstract multiplicative structure for Chaum Blind-RSA OPRF modulo `N`. -/
structure RSAMonoid (R : Type) where
  mul : R → R → R
  one : R
  pow : R → Nat → R
  mul_assoc : ∀ a b c, mul (mul a b) c = mul a (mul b c)
  mul_one : ∀ a, mul a one = a
  pow_mul : ∀ a b k, pow (mul a b) k = mul (pow a k) (pow b k)

/-- **Chaum Blind-RSA OPRF Correctness**:
    Given `(r^e)^d = r` and `r * r_inv = 1`, unblinding `(h * r^e)^d * r_inv`
    recovers `h^d` identically. -/
theorem rsa_oprf_unblind_correct {R : Type} (rsa : RSAMonoid R)
    (h r r_inv : R) (e d : Nat)
    (hrsa : rsa.pow (rsa.pow r e) d = r)
    (hinv : rsa.mul r r_inv = rsa.one) :
    rsa.mul (rsa.pow (rsa.mul h (rsa.pow r e)) d) r_inv = rsa.pow h d := by
  rw [rsa.pow_mul, hrsa, rsa.mul_assoc, hinv, rsa.mul_one]

/-- **Chaum Blind-RSA Blinding Privacy**:
    In a commutative multiplicative group with `e`-th root extraction `(x^d)^e = x`,
    any blinded value `h1 * r1^e` is identically attainable from `h2` using
    `r2 = r1 * (h1 * h2_inv)^d`. -/
theorem rsa_oprf_blinding_private {R : Type} (rsa : RSAMonoid R)
    (mul_comm : ∀ a b, rsa.mul a b = rsa.mul b a)
    (h1 h2 h2_inv r1 : R) (e d : Nat)
    (hinv2 : rsa.mul h2 h2_inv = rsa.one)
    (hed : ∀ x, rsa.pow (rsa.pow x d) e = x) :
    ∃ r2 : R, rsa.mul h2 (rsa.pow r2 e) = rsa.mul h1 (rsa.pow r1 e) := by
  refine ⟨rsa.mul r1 (rsa.pow (rsa.mul h1 h2_inv) d), ?_⟩
  rw [rsa.pow_mul, hed]
  rw [mul_comm (rsa.pow r1 e) (rsa.mul h1 h2_inv)]
  rw [← rsa.mul_assoc h2 (rsa.mul h1 h2_inv) (rsa.pow r1 e)]
  have hcancel : rsa.mul h2 (rsa.mul h1 h2_inv) = h1 := by
    rw [mul_comm h1 h2_inv, ← rsa.mul_assoc, hinv2, mul_comm, rsa.mul_one]
  rw [hcancel]

end PMSet.OPRF
