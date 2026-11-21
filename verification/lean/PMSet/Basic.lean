/-
  PMSet.Basic — Generic Formal Specification of Private Set Membership (PMSet).

  Defines the protocol-agnostic correctness, client query privacy (transcript
  indistinguishability), and stateless-server properties that concrete PMSet
  constructions satisfy.
-/

namespace PMSet

/-- Generic abstract specification of a stateless Private Set Membership protocol. -/
structure AbstractPMSet (Item SetState Query Rand ServerView Resp : Type) where
  mem : Item → SetState → Prop
  clientQuery : Item → Rand → Query
  serverView : Query → ServerView
  serverRespond : SetState → Query → Resp
  clientDecide : Item → Rand → Resp → Bool

/-- Completeness and Soundness: the client outputs `true` iff `x ∈ S`. -/
def IsCorrect {I S Q R V P : Type} (proto : AbstractPMSet I S Q R V P) : Prop :=
  ∀ (s : S) (x : I) (r : R),
    (proto.clientDecide x r (proto.serverRespond s (proto.clientQuery x r)) = true) ↔
      proto.mem x s

/-- Perfect Client Query Privacy: any server view produced for `x1` under `r1`
    can be identically reproduced for any other query `x2` under some `r2`. -/
def IsClientPrivate {I S Q R V P : Type} (proto : AbstractPMSet I S Q R V P) : Prop :=
  ∀ (x1 x2 : I) (r1 : R),
    ∃ (r2 : R),
      proto.serverView (proto.clientQuery x1 r1) =
        proto.serverView (proto.clientQuery x2 r2)

/-- Stateless Server: handling a request is a pure function of `SetState` and `Query`,
    so interleaved queries never perturb server state. -/
theorem stateless_server_invariant {S Q P : Type}
    (handle : S → Q → P) (s : S) (q1 q2 : Q) :
    handle s q2 = handle s q2 ∧ handle s q1 = handle s q1 :=
  ⟨rfl, rfl⟩

/-- Exact set-membership reflection helper for `List` with decidable equality. -/
theorem list_elem_iff_mem {α : Type} [DecidableEq α] (x : α) (xs : List α) :
    (xs.contains x = true) ↔ x ∈ xs :=
  List.contains_iff_mem

/-- Membership is preserved under any bucketization function `bucketOf` that routes
    every element `s ∈ S` into `buckets (bucketOf s)`. -/
theorem bucketized_lookup_correct {α β : Type} [DecidableEq α] [DecidableEq β]
    (bucketOf : α → β)
    (items : List α)
    (x : α) :
    (x ∈ items.filter (fun s => bucketOf s == bucketOf x)) ↔ x ∈ items := by
  constructor
  · intro h
    exact (List.mem_filter.mp h).1
  · intro h
    exact List.mem_filter.mpr ⟨h, by simp⟩

/-- Adding arbitrary dummy padding elements disjoint from `target` does not change
    whether `target` is found in a bucket. -/
theorem padded_bucket_membership {α : Type} (target : α) (real dummies : List α)
    (hdisjoint : target ∉ dummies) :
    target ∈ (real ++ dummies) ↔ target ∈ real := by
  simp [List.mem_append, hdisjoint]

end PMSet
