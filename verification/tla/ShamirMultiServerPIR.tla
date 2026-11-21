---- MODULE ShamirMultiServerPIR ----
EXTENDS Naturals, FiniteSets

(*
  k-Server t-Private Information-Theoretic Shamir PIR (CGKS) Specification.
  Models k = 3 isolated servers, privacy threshold t = 1 (degree-1 polynomial)
  over prime field F_Prime (Prime = 5), evaluation points x = 1, 2, 3.
  Lagrange weights at X = 0 for {x1=1, x2=2}: w1 = 2, w2 = -1 == 4 (mod 5).
  Checks:
    - Lagrange recovery recovers exact bucket value DB[targetBucket]
    - 1-Privacy: any single server's observed share vector is information-
      theoretically consistent with EVERY target bucket!
*)

CONSTANTS Prime, BucketCount, Items

VARIABLES
    serverSet,
    db,
    initialDB,
    stage,
    query,
    slopes,         \* Random degree-1 polynomial slope a_b per bucket b
    shares,         \* [1..3 -> [Buckets -> 0..(Prime-1)]]
    responses,      \* [1..3 -> 0..(Prime-1)]
    recovered,
    result

vars == <<serverSet, db, initialDB, stage, query, slopes, shares, responses, recovered, result>>

Buckets == 0 .. (BucketCount - 1)
Servers == {1, 2, 3}
BucketOf(x) == x % BucketCount

\* Encode whether bucket b holds a member matching bitmask (for 1 item per bucket: 1 iff b \in serverSet)
BuildDB(S) == [b \in Buckets |-> IF b \in S THEN 1 ELSE 0]

RECURSIVE DotProd(_, _, _)
DotProd(idxs, vec, vals) ==
    IF idxs = {} THEN 0
    ELSE
        LET i == CHOOSE k \in idxs : TRUE
        IN (vec[i] * vals[i] + DotProd(idxs \ {i}, vec, vals)) % Prime

Init ==
    /\ serverSet \in SUBSET Items
    /\ db = BuildDB(serverSet)
    /\ initialDB = db
    /\ stage = "init"
    /\ query \in Items
    /\ slopes \in [Buckets -> 0 .. (Prime - 1)]
    /\ shares = [j \in Servers |->
                    [b \in Buckets |->
                        ((IF b = BucketOf(query) THEN 1 ELSE 0) + slopes[b] * j) % Prime]]
    /\ responses = [j \in Servers |-> 0]
    /\ recovered = 0
    /\ result = FALSE

ServersAnswer ==
    /\ stage = "init"
    /\ responses' = [j \in Servers |-> DotProd(Buckets, shares[j], db)]
    /\ stage' = "responded"
    /\ UNCHANGED <<serverSet, db, initialDB, query, slopes, shares, recovered, result>>

ClientLagrangeReconstruct ==
    /\ stage = "responded"
    \* Lagrange weights at 0 for x1=1, x2=2: w1 = 2, w2 = -1 mod Prime
    /\ recovered' = (2 * responses[1] + (Prime - 1) * responses[2]) % Prime
    /\ result' = (((2 * responses[1] + (Prime - 1) * responses[2]) % Prime) = 1)
    /\ stage' = "done"
    /\ UNCHANGED <<serverSet, db, initialDB, query, slopes, shares, responses>>

Done ==
    /\ stage = "done"
    /\ UNCHANGED vars

Next == ServersAnswer \/ ClientLagrangeReconstruct \/ Done
Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ serverSet \subseteq Items
    /\ stage \in {"init", "responded", "done"}
    /\ result \in BOOLEAN

StatelessReplicas == db = initialDB

MembershipCorrectness ==
    stage = "done" => (result <=> (query \in serverSet))

\* Information-theoretic 1-privacy: for ANY single server j and ANY alternative
\* target bucket altB, there exists a slope vector reproducing server j's EXACT view!
SingleServerITPrivacy ==
    \A j \in Servers :
        \A altB \in Buckets :
            \E altSlopes \in [Buckets -> 0 .. (Prime - 1)] :
                \A b \in Buckets :
                    ((IF b = altB THEN 1 ELSE 0) + altSlopes[b] * j) % Prime = shares[j][b]

====
