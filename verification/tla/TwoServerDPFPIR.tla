---- MODULE TwoServerDPFPIR ----
EXTENDS Naturals, FiniteSets

(*
  2-Server Non-Colluding BGI15 DPF/FSS PIR + OPRF Specification.
  Explicitly models two isolated server replicas (Replica 0 and Replica 1)
  whose share vectors XOR to the unit point function e_{targetBucket}.
*)

CONSTANTS BucketCount, Items

VARIABLES
    serverSet,
    replica0DB,
    replica1DB,
    stage,
    query,
    share0,         \* Isolated DPF bit vector sent ONLY to Replica 0
    share1,         \* Isolated DPF bit vector sent ONLY to Replica 1
    resp0,
    resp1,
    result

vars == <<serverSet, replica0DB, replica1DB, stage, query, share0, share1, resp0, resp1, result>>

Buckets == 0 .. (BucketCount - 1)
BucketOf(x) == x % BucketCount

\* Bitmask representation of bucket contents (bit x set iff x in bucket)
RECURSIVE BucketMask(_, _)
BucketMask(b, S) ==
    IF S = {} THEN 0
    ELSE
        LET x == CHOOSE e \in S : TRUE
            bit == IF BucketOf(x) = b THEN 2^x ELSE 0
        IN bit + BucketMask(b, S \ {x})

\* Symmetric difference of two subsets models bytewise XOR of bucket records
SymDiff(A, B) == (A \ B) \cup (B \ A)

RECURSIVE XorEval(_, _, _)
XorEval(idxs, sel, db) ==
    IF idxs = {} THEN {}
    ELSE
        LET i == CHOOSE k \in idxs : TRUE
            rest == XorEval(idxs \ {i}, sel, db)
        IN IF sel[i] = 1 THEN SymDiff(rest, db[i]) ELSE rest

BuildDB(S) == [b \in Buckets |-> { x \in S : BucketOf(x) = b }]

Init ==
    /\ serverSet \in SUBSET Items
    /\ replica0DB = BuildDB(serverSet)
    /\ replica1DB = BuildDB(serverSet)
    /\ stage = "init"
    /\ query \in Items
    /\ share0 \in [Buckets -> {0, 1}]
    /\ share1 = [b \in Buckets |->
                    IF b = BucketOf(query) THEN (1 - share0[b]) ELSE share0[b]]
    /\ resp0 = {}
    /\ resp1 = {}
    /\ result = FALSE

ReplicasEvaluate ==
    /\ stage = "init"
    \* Replica 0 sees ONLY share0; Replica 1 sees ONLY share1
    /\ resp0' = XorEval(Buckets, share0, replica0DB)
    /\ resp1' = XorEval(Buckets, share1, replica1DB)
    /\ stage' = "responded"
    /\ UNCHANGED <<serverSet, replica0DB, replica1DB, query, share0, share1, result>>

ClientCombine ==
    /\ stage = "responded"
    /\ result' = (query \in SymDiff(resp0, resp1))
    /\ stage' = "done"
    /\ UNCHANGED <<serverSet, replica0DB, replica1DB, query, share0, share1, resp0, resp1>>

Done ==
    /\ stage = "done"
    /\ UNCHANGED vars

Next == ReplicasEvaluate \/ ClientCombine \/ Done
Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ serverSet \subseteq Items
    /\ stage \in {"init", "responded", "done"}
    /\ result \in BOOLEAN

StrictReplicaConsistency == replica0DB = replica1DB

DPFXorInvariant ==
    \A b \in Buckets :
        ((share0[b] + share1[b]) % 2 = 1) <=> (b = BucketOf(query))

MembershipCorrectness ==
    stage = "done" => (result <=> (query \in serverSet))

\* Single-replica privacy: share0 alone is consistent with ANY target bucket altB!
SingleReplicaPrivacy ==
    \A altB \in Buckets :
        \E altShare1 \in [Buckets -> {0, 1}] :
            \A b \in Buckets :
                ((share0[b] + altShare1[b]) % 2 = 1) <=> (b = altB)

====
