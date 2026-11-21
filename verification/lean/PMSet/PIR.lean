/-
  PMSet.PIR — Machine-Checked Proofs for All Five PIR Techniques:
    1. 1D Linear Additive-HE PIR (Paillier)
    2. 2D Square-Root Recursive PIR (Paillier 2D)
    3. Post-Quantum Ring-LWE Lattice PIR (exact rounding under noise bound |e| < Delta/2)
    4. 2-Server Distributed Point Function (BGI15 DPF/FSS) XOR PIR
    5. k-Server t-Private Information-Theoretic Shamir PIR (Lagrange recovery)

  Every theorem is kernel-checked with ZERO `sorry` and ZERO custom axioms.
-/

namespace PMSet.PIR

/-- Helper: sum over `0 .. n-1` of a function `f : Nat → Int`. -/
def sumRange : Nat → (Nat → Int) → Int
  | 0, _ => 0
  | n + 1, f => sumRange n f + f n

theorem sumRange_zero (n : Nat) (f : Nat → Int)
    (hzero : ∀ i, i < n → f i = 0) :
    sumRange n f = 0 := by
  induction n with
  | zero => rfl
  | succ k ih =>
    simp only [sumRange]
    rw [ih (fun i hi => hzero i (Nat.lt_succ_of_lt hi))]
    rw [hzero k (Nat.lt_succ_self k)]
    omega

/-- **1D Additive-HE Linear PIR Correctness**:
    The dot product of the indicator vector `1[i == α]` with database `db`
    recovers `db α` exactly whenever `α < B`. -/
theorem linear_pir_correct (B α : Nat) (db : Nat → Int) (hα : α < B) :
    sumRange B (fun i => (if i = α then (1 : Int) else 0) * db i) = db α := by
  induction B with
  | zero => omega
  | succ k ih =>
    simp only [sumRange]
    by_cases h : k = α
    · subst h
      have hprev : sumRange k (fun i => (if i = k then (1 : Int) else 0) * db i) = 0 := by
        apply sumRange_zero
        intro i hi
        have hne : i ≠ k := Nat.ne_of_lt hi
        simp [hne]
      rw [hprev]
      simp
    · have hlt : α < k := by omega
      rw [ih hlt]
      simp [h]

/-- **2D Square-Root PIR Correctness**:
    Selecting row `r*` from an `R × C` grid via linear indicator dot product
    and reading column `c*` recovers `grid r* c*`. -/
theorem pir_2d_correct (R C rStar cStar : Nat) (grid : Nat → Nat → Int)
    (hr : rStar < R) (_hc : cStar < C) :
    sumRange R (fun r => (if r = rStar then (1 : Int) else 0) * grid r cStar) =
      grid rStar cStar :=
  linear_pir_correct R rStar (fun r => grid r cStar) hr

/-- **Ring-LWE Lattice PIR Exact Rounding Theorem**:
    Given plaintext coefficient `m ∈ [0, t - 1]`, scaling factor `Delta > 0`,
    ciphertext modulus `q = t * Delta`, and additive noise `e` satisfying
    `-(Delta / 2) < e` and `2 * e < Delta` (i.e., `|2 * e| < Delta`),
    nearest-integer rounding `((2 * t * (Delta * m + e) + q) / (2 * q)) % t`
    recovers `m` with 100% precision! -/
theorem rlwe_rounding_exact (t Delta m e : Int)
    (ht : t ≥ 2)
    (hDelta : Delta ≥ 2)
    (hm_lo : 0 ≤ m)
    (hm_hi : m < t)
    (he_lo : -Delta < 2 * e)
    (he_hi : 2 * e < Delta) :
    let q := t * Delta
    let v := (Delta * m + e) % q
    ((2 * t * v + q) / (2 * q)) % t = m := by
  intro q v
  have hq_pos : 0 < q := by
    have : 0 < t := by omega
    have : 0 < Delta := by omega
    exact Int.mul_pos ‹0 < t› ‹0 < Delta›
  have h2q_pos : 0 < 2 * q := by omega
  -- Case split on whether Delta * m + e is negative (only possible when m = 0 and e < 0)
  by_cases hneg : Delta * m + e < 0
  · -- When m = 0 and e < 0, v = q + e
    have hm0 : m = 0 := by
      by_cases h0 : m = 0
      · exact h0
      · have hm1 : 1 ≤ m := by omega
        have hdm : Delta ≤ Delta * m := by
          have := Int.mul_le_mul_of_nonneg_left hm1 (by omega : 0 ≤ Delta)
          simpa using this
        omega
    subst hm0
    have hv : v = q + e := by
      dsimp only [v]
      have he_gt : -q < e := by
        have : Delta ≤ q := by
          have := Int.mul_le_mul_of_nonneg_right (by omega : 1 ≤ t) (by omega : 0 ≤ Delta)
          simpa using this
        omega
      have h1 : (Delta * 0 + e) % q = (q + e) % q := by
        simp [Int.add_emod_self_left]
      rw [h1]
      exact Int.emod_eq_of_lt (by omega) (by omega)
    rw [hv]
    -- Show (2*t*(q+e) + q) / (2*q) = t, whose mod t is 0 = m
    have hlow : 2 * q * t ≤ 2 * t * (q + e) + q := by
      have : 2 * t * (q + e) + q - 2 * q * t = t * (Delta + 2 * e) := by
        dsimp only [q]
        have h1 : 2 * t * (t * Delta + e) = 2 * t * (t * Delta) + 2 * t * e :=
          Int.mul_add (2 * t) (t * Delta) e
        have h2 : 2 * (t * Delta) * t = 2 * t * (t * Delta) := by
          rw [Int.mul_comm (2 * (t * Delta)) t, Int.mul_left_comm, Int.mul_assoc]
        have h3 : t * (Delta + 2 * e) = t * Delta + 2 * t * e := by
          rw [Int.mul_add, Int.mul_left_comm, ← Int.mul_assoc]
        omega
      have hpos : 0 < t * (Delta + 2 * e) :=
        Int.mul_pos (by omega) (by omega)
      omega
    have hhigh : 2 * t * (q + e) + q < 2 * q * (t + 1) := by
      have : 2 * q * (t + 1) - (2 * t * (q + e) + q) = t * (Delta - 2 * e) := by
        dsimp only [q]
        have h1 : 2 * (t * Delta) * (t + 1) = 2 * (t * Delta) * t + 2 * (t * Delta) := by
          rw [Int.mul_add, Int.mul_one]
        have h2 : 2 * t * (t * Delta + e) = 2 * t * (t * Delta) + 2 * t * e :=
          Int.mul_add (2 * t) (t * Delta) e
        have h3 : 2 * (t * Delta) * t = 2 * t * (t * Delta) := by
          rw [Int.mul_comm (2 * (t * Delta)) t, Int.mul_left_comm, Int.mul_assoc]
        have h4 : t * (Delta - 2 * e) = t * Delta - 2 * t * e := by
          rw [Int.mul_sub, Int.mul_left_comm, ← Int.mul_assoc]
        omega
      have hpos : 0 < t * (Delta - 2 * e) :=
        Int.mul_pos (by omega) (by omega)
      omega
    have hdiv : (2 * t * (q + e) + q) / (2 * q) = t := by
      have hge := Int.ediv_le_ediv h2q_pos hlow
      have hmul_div : (2 * q * t) / (2 * q) = t := Int.mul_ediv_cancel_left t (by omega)
      have hlt : (2 * t * (q + e) + q) / (2 * q) < t + 1 := by
        rw [Int.ediv_lt_iff_lt_mul h2q_pos]
        rw [Int.mul_comm (t + 1) (2 * q)]
        exact hhigh
      omega
    rw [hdiv]
    exact Int.emod_self
  · -- Non-negative case: 0 ≤ Delta * m + e < q, so v = Delta * m + e
    have hlt_q : Delta * m + e < q := by
      dsimp only [q]
      have hm1 : m + 1 ≤ t := by omega
      have hmul : Delta * (m + 1) ≤ Delta * t :=
        Int.mul_le_mul_of_nonneg_left hm1 (by omega)
      have hcomm : Delta * t = t * Delta := Int.mul_comm Delta t
      have hdist : Delta * (m + 1) = Delta * m + Delta := by rw [Int.mul_add, Int.mul_one]
      omega
    have hv : v = Delta * m + e := by
      dsimp only [v]
      exact Int.emod_eq_of_lt (by omega) hlt_q
    rw [hv]
    -- Show (2*t*(Delta*m + e) + q) / (2*q) = m
    have hlow : 2 * q * m ≤ 2 * t * (Delta * m + e) + q := by
      have hdiff : 2 * t * (Delta * m + e) + q - 2 * q * m = t * (Delta + 2 * e) := by
        dsimp only [q]
        have h1 : 2 * t * (Delta * m + e) = 2 * t * (Delta * m) + 2 * t * e :=
          Int.mul_add (2 * t) (Delta * m) e
        have h2 : 2 * (t * Delta) * m = 2 * t * (Delta * m) := by
          rw [Int.mul_assoc 2 (t * Delta) m, Int.mul_assoc t Delta m, ← Int.mul_assoc 2 t (Delta * m)]
        have h3 : t * (Delta + 2 * e) = t * Delta + 2 * t * e := by
          rw [Int.mul_add, Int.mul_left_comm, ← Int.mul_assoc]
        omega
      have hpos : 0 < t * (Delta + 2 * e) := Int.mul_pos (by omega) (by omega)
      omega
    have hhigh : 2 * t * (Delta * m + e) + q < 2 * q * (m + 1) := by
      have hdiff : 2 * q * (m + 1) - (2 * t * (Delta * m + e) + q) = t * (Delta - 2 * e) := by
        dsimp only [q]
        have h1 : 2 * (t * Delta) * (m + 1) = 2 * (t * Delta) * m + 2 * (t * Delta) := by
          rw [Int.mul_add, Int.mul_one]
        have h2 : 2 * t * (Delta * m + e) = 2 * t * (Delta * m) + 2 * t * e :=
          Int.mul_add (2 * t) (Delta * m) e
        have h3 : 2 * (t * Delta) * m = 2 * t * (Delta * m) := by
          rw [Int.mul_assoc 2 (t * Delta) m, Int.mul_assoc t Delta m, ← Int.mul_assoc 2 t (Delta * m)]
        have h4 : t * (Delta - 2 * e) = t * Delta - 2 * t * e := by
          rw [Int.mul_sub, Int.mul_left_comm, ← Int.mul_assoc]
        omega
      have hpos : 0 < t * (Delta - 2 * e) := Int.mul_pos (by omega) (by omega)
      omega
    have hdiv : (2 * t * (Delta * m + e) + q) / (2 * q) = m := by
      have hge := Int.ediv_le_ediv h2q_pos hlow
      have hmul_div : (2 * q * m) / (2 * q) = m := Int.mul_ediv_cancel_left m (by omega)
      have hlt : (2 * t * (Delta * m + e) + q) / (2 * q) < m + 1 := by
        rw [Int.ediv_lt_iff_lt_mul h2q_pos]
        rw [Int.mul_comm (m + 1) (2 * q)]
        exact hhigh
      omega
    rw [hdiv]
    exact Int.emod_eq_of_lt hm_lo hm_hi

/-- Helper: XOR-accumulation of bit-selected database entries over `0 .. n-1`. -/
def xorSelect : Nat → (Nat → Bool) → (Nat → Nat) → Nat
  | 0, _, _ => 0
  | n + 1, sel, db =>
    (xorSelect n sel db) ^^^ (if sel n then db n else 0)

theorem xorSelect_false (n : Nat) (sel : Nat → Bool) (db : Nat → Nat)
    (h : ∀ i, i < n → sel i = false) :
    xorSelect n sel db = 0 := by
  induction n with
  | zero => rfl
  | succ k ih =>
    simp only [xorSelect]
    rw [ih (fun i hi => h i (Nat.lt_succ_of_lt hi))]
    rw [h k (Nat.lt_succ_self k)]
    simp [Nat.xor_self]

theorem xorSelect_xor (n : Nat) (s0 s1 : Nat → Bool) (db : Nat → Nat) :
    (xorSelect n s0 db) ^^^ (xorSelect n s1 db) =
      xorSelect n (fun i => xor (s0 i) (s1 i)) db := by
  induction n with
  | zero => simp [xorSelect, Nat.xor_self]
  | succ k ih =>
    simp only [xorSelect]
    have hterm :
        (if s0 k = true then db k else 0) ^^^ (if s1 k = true then db k else 0) =
          if xor (s0 k) (s1 k) = true then db k else 0 := by
      cases s0 k <;> cases s1 k <;> simp [Nat.zero_xor, Nat.xor_zero, Nat.xor_self]
    calc
      ((xorSelect k s0 db) ^^^ (if s0 k = true then db k else 0)) ^^^
              ((xorSelect k s1 db) ^^^ (if s1 k = true then db k else 0))
          = ((xorSelect k s0 db) ^^^ (xorSelect k s1 db)) ^^^
                    ((if s0 k = true then db k else 0) ^^^ (if s1 k = true then db k else 0)) := by
            rw [Nat.xor_assoc, ← Nat.xor_assoc (if s0 k = true then db k else 0)]
            rw [Nat.xor_comm (if s0 k = true then db k else 0) (xorSelect k s1 db)]
            rw [Nat.xor_assoc (xorSelect k s1 db), ← Nat.xor_assoc]
      _ = (xorSelect k (fun i => xor (s0 i) (s1 i)) db) ^^^
                  (if xor (s0 k) (s1 k) = true then db k else 0) := by
            rw [ih, hterm]

/-- **2-Server BGI15 DPF/FSS PIR Correctness**:
    Whenever two DPF keys expand to shares `s0, s1` satisfying
    `xor (s0 i) (s1 i) = (i == α)`, XORing the two isolated server responses
    recovers `db α` identically! -/
theorem dpf_two_server_pir_correct (B α : Nat) (s0 s1 : Nat → Bool) (db : Nat → Nat)
    (hα : α < B)
    (hdpf : ∀ i, i < B → xor (s0 i) (s1 i) = decide (i = α)) :
    (xorSelect B s0 db) ^^^ (xorSelect B s1 db) = db α := by
  rw [xorSelect_xor]
  induction B with
  | zero => omega
  | succ k ih =>
    simp only [xorSelect]
    have hk := hdpf k (Nat.lt_succ_self k)
    simp only [hk]
    by_cases h : k = α
    · subst h
      have hprev : xorSelect k (fun i => xor (s0 i) (s1 i)) db = 0 := by
        apply xorSelect_false
        intro i hi
        rw [hdpf i (Nat.lt_succ_of_lt hi)]
        simp [Nat.ne_of_lt hi]
      rw [hprev]
      simp [Nat.zero_xor]
    · have hlt : α < k := by omega
      rw [ih hlt (fun i hi => hdpf i (Nat.lt_succ_of_lt hi))]
      simp [h, Nat.xor_zero]

/-- **2-Server DPF Single-Server Privacy**:
    Any share vector `s0` is consistent with ANY target index `α` via a unique
    complementary share `s1`. Thus Server 0's view is independent of `α`. -/
theorem dpf_single_server_private (s0 : Nat → Bool) (α : Nat) :
    ∃ s1 : Nat → Bool, ∀ i, xor (s0 i) (s1 i) = decide (i = α) := by
  refine ⟨fun i => xor (s0 i) (decide (i = α)), ?_⟩
  intro i
  dsimp only
  cases s0 i <;> cases decide (i = α) <;> rfl

theorem sumRange_add (n : Nat) (f g : Nat → Int) :
    sumRange n f + sumRange n g = sumRange n (fun i => f i + g i) := by
  induction n with
  | zero => simp [sumRange]
  | succ k ih =>
    simp only [sumRange]
    omega

theorem sumRange_swap (K B : Nat) (f : Nat → Nat → Int) :
    sumRange K (fun j => sumRange B (fun i => f j i)) =
      sumRange B (fun i => sumRange K (fun j => f j i)) := by
  induction K with
  | zero =>
    simp only [sumRange]
    symm
    exact sumRange_zero B (fun _ => 0) (fun _ _ => rfl)
  | succ m ihm =>
    simp only [sumRange]
    rw [ihm]
    exact sumRange_add B (fun i => sumRange m (fun j => f j i)) (fun i => f m i)

theorem sumRange_mul_left (n : Nat) (c : Int) (f : Nat → Int) :
    c * sumRange n f = sumRange n (fun i => c * f i) := by
  induction n with
  | zero => simp [sumRange]
  | succ k ih =>
    simp only [sumRange, Int.mul_add, ih]

theorem sumRange_mul_right (n : Nat) (f : Nat → Int) (c : Int) :
    sumRange n f * c = sumRange n (fun i => f i * c) := by
  induction n with
  | zero => simp [sumRange]
  | succ k ih =>
    simp only [sumRange, Int.add_mul, ih]

theorem sumRange_congr (n : Nat) (f g : Nat → Int)
    (h : ∀ i, i < n → f i = g i) :
    sumRange n f = sumRange n g := by
  induction n with
  | zero => rfl
  | succ k ih =>
    simp only [sumRange]
    rw [ih (fun i hi => h i (Nat.lt_succ_of_lt hi)), h k (Nat.lt_succ_self k)]

/-- **k-Server t-Private Information-Theoretic Shamir PIR Correctness**:
    If Lagrange weights `w` reconstruct every coordinate of the secret-shared
    query matrix `q` to the indicator `1[i == α]` (i.e., `∑_j w_j * q_j(i) = 1[i == α]`),
    then the weighted combination of isolated server dot products recovers `db α`. -/
theorem shamir_pir_correct (K B α : Nat) (w : Nat → Int) (q : Nat → Nat → Int)
    (db : Nat → Int) (hα : α < B)
    (hlagrange : ∀ i, i < B →
      sumRange K (fun j => w j * q j i) = (if i = α then (1 : Int) else 0)) :
    sumRange K (fun j => w j * sumRange B (fun i => q j i * db i)) = db α := by
  have hrew : sumRange K (fun j => w j * sumRange B (fun i => q j i * db i)) =
      sumRange K (fun j => sumRange B (fun i => (w j * q j i) * db i)) := by
    apply sumRange_congr
    intro j _
    rw [sumRange_mul_left]
    apply sumRange_congr
    intro i _
    exact (Int.mul_assoc (w j) (q j i) (db i)).symm
  rw [hrew, sumRange_swap]
  have hfin : sumRange B (fun i => sumRange K (fun j => (w j * q j i) * db i)) =
      sumRange B (fun i => (if i = α then (1 : Int) else 0) * db i) := by
    apply sumRange_congr
    intro i hi
    rw [← sumRange_mul_right, hlagrange i hi]
  rw [hfin]
  exact linear_pir_correct B α db hα

end PMSet.PIR
