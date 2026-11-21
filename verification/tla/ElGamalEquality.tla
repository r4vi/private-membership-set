---- MODULE ElGamalEquality ----
EXTENDS Naturals, FiniteSets

(*
  1-Round Exponential ElGamal Randomized Homomorphic Zero-Test + Shuffle.
  Server masks each (x - s) with fresh non-zero scalar r_s in 1..(Prime-1)
  and returns the multiset/set of masked values; client tests whether 0 appears.
*)

CONSTANTS Prime, Items

VARIABLES
    serverSet,
    initialServerSet,
    stage,
    query,
    masks,
    responseSet,
    result

vars == <<serverSet, initialServerSet, stage, query, masks, responseSet, result>>

Init ==
    /\ serverSet \in SUBSET Items
    /\ initialServerSet = serverSet
    /\ stage = "init"
    /\ query \in Items
    /\ masks \in [Items -> 1 .. (Prime - 1)]
    /\ responseSet = {}
    /\ result = FALSE

ServerMaskAndShuffle ==
    /\ stage = "init"
    /\ responseSet' = { (masks[s] * ((query + Prime - s) % Prime)) % Prime : s \in serverSet }
    /\ stage' = "responded"
    /\ UNCHANGED <<serverSet, initialServerSet, query, masks, result>>

ClientZeroTest ==
    /\ stage = "responded"
    /\ result' = (0 \in responseSet)
    /\ stage' = "done"
    /\ UNCHANGED <<serverSet, initialServerSet, query, masks, responseSet>>

Done ==
    /\ stage = "done"
    /\ UNCHANGED vars

Next == ServerMaskAndShuffle \/ ClientZeroTest \/ Done
Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ serverSet \subseteq Items
    /\ stage \in {"init", "responded", "done"}
    /\ result \in BOOLEAN

StatelessServer == serverSet = initialServerSet

MembershipCorrectness ==
    stage = "done" => (result <=> (query \in serverSet))

NonMemberZeroFree ==
    (stage = "done" /\ query \notin serverSet) => (0 \notin responseSet)

====
