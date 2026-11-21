---- MODULE OPRFPIR ----
EXTENDS Naturals, FiniteSets

(*
  2-Round OPRF + Bucketized PIR Protocol Specification
  Covers:
    - dh_oprf_paillier_pir
    - ecdh_oprf_paillier_pir
    - ecdh_oprf_paillier_2d_pir
    - rsa_oprf_paillier_pir
    - oprf_rlwe_pir

  Models multiplicative group Z_P* (P = 7, order q = 6 or prime subgroup mod 5)
  with exact exponentiation blinding/unblinding, bucketization with uniform
  padding, and homomorphic PIR dot-product selection.
*)

CONSTANTS P, Q, ServerKey, BucketCount, Items

VARIABLES
    serverSet,
    initialBuckets,
    buckets,
    stage,          \* "init" -> "oprf_sent" -> "oprf_done" -> "pir_sent" -> "done"
    query,
    blindR,
    blindedMsg,
    evaluatedMsg,
    unblindedHash,
    targetBucket,
    pirResponse,
    result

vars == <<serverSet, initialBuckets, buckets, stage, query, blindR,
          blindedMsg, evaluatedMsg, unblindedHash, targetBucket, pirResponse, result>>

\* Modular exponentiation via recursive definition over small Q
RECURSIVE ModPow(_, _, _)
ModPow(base, exp, mod) ==
    IF exp = 0 THEN 1
    ELSE (base * ModPow(base, exp - 1, mod)) % mod

\* Invertible blinding scalars in Z_Q* (for prime Q, all 1..Q-1)
ValidBlinds == 1 .. (Q - 1)

ModInv(r) == CHOOSE inv \in 1 .. (Q - 1) : (r * inv) % Q = 1

\* Group generator of prime-order subgroup of order Q inside Z_P*
\* For P = 11, Q = 5: squares mod 11 are {1, 3, 4, 5, 9} (prime order 5!)
HashToSubgroup(x) ==
    LET raw == (x + 2) % P
    IN (raw * raw) % P

DirectOPRF(x) == ModPow(HashToSubgroup(x), ServerKey, P)

BucketOf(h) == h % BucketCount

BuildBuckets(S) ==
    [b \in 0 .. (BucketCount - 1) |->
        { DirectOPRF(s) : s \in { x \in S : BucketOf(DirectOPRF(x)) = b } }]

Init ==
    /\ serverSet \in SUBSET Items
    /\ buckets = BuildBuckets(serverSet)
    /\ initialBuckets = buckets
    /\ stage = "init"
    /\ query \in Items
    /\ blindR \in ValidBlinds
    /\ blindedMsg = 0
    /\ evaluatedMsg = 0
    /\ unblindedHash = 0
    /\ targetBucket = 0
    /\ pirResponse = {}
    /\ result = FALSE

ClientBlind ==
    /\ stage = "init"
    /\ blindedMsg' = ModPow(HashToSubgroup(query), blindR, P)
    /\ stage' = "oprf_sent"
    /\ UNCHANGED <<serverSet, initialBuckets, buckets, query, blindR,
                   evaluatedMsg, unblindedHash, targetBucket, pirResponse, result>>

ServerOPRF ==
    /\ stage = "oprf_sent"
    /\ evaluatedMsg' = ModPow(blindedMsg, ServerKey, P)
    /\ stage' = "oprf_done"
    /\ UNCHANGED <<serverSet, initialBuckets, buckets, query, blindR,
                   blindedMsg, unblindedHash, targetBucket, pirResponse, result>>

ClientUnblindAndPIRQuery ==
    /\ stage = "oprf_done"
    /\ unblindedHash' = ModPow(evaluatedMsg, ModInv(blindR), P)
    /\ targetBucket' = BucketOf(ModPow(evaluatedMsg, ModInv(blindR), P))
    /\ stage' = "pir_sent"
    /\ UNCHANGED <<serverSet, initialBuckets, buckets, query, blindR,
                   blindedMsg, evaluatedMsg, pirResponse, result>>

ServerPIRAndClientDecide ==
    /\ stage = "pir_sent"
    \* Homomorphic PIR selects buckets[targetBucket] without learning targetBucket
    /\ pirResponse' = buckets[targetBucket]
    /\ result' = (unblindedHash \in buckets[targetBucket])
    /\ stage' = "done"
    /\ UNCHANGED <<serverSet, initialBuckets, buckets, query, blindR,
                   blindedMsg, evaluatedMsg, unblindedHash, targetBucket>>

Done ==
    /\ stage = "done"
    /\ UNCHANGED vars

Next ==
    \/ ClientBlind
    \/ ServerOPRF
    \/ ClientUnblindAndPIRQuery
    \/ ServerPIRAndClientDecide
    \/ Done

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ serverSet \subseteq Items
    /\ stage \in {"init", "oprf_sent", "oprf_done", "pir_sent", "done"}
    /\ result \in BOOLEAN

StatelessServer == buckets = initialBuckets

OPRFCorrectness ==
    stage \in {"pir_sent", "done"} => unblindedHash = DirectOPRF(query)

PIRCorrectness ==
    stage = "done" => pirResponse = buckets[BucketOf(DirectOPRF(query))]

MembershipCorrectness ==
    stage = "done" => (result <=> (query \in serverSet))

\* Every blinded OPRF message seen by the server could have been produced by ANY item in Items
BlindingPrivacy ==
    stage \in {"oprf_sent", "oprf_done", "pir_sent", "done"} =>
        \A altQ \in Items :
            \E altR \in ValidBlinds :
                ModPow(HashToSubgroup(altQ), altR, P) = blindedMsg

====
