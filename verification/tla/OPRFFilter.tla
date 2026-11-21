---- MODULE OPRFFilter ----
EXTENDS Naturals, FiniteSets

(*
  1-Round Amortized O(1) ECDH-OPRF + Compact Encrypted Set Specification.
  Server publishes opaque OPRF tags once; client completes membership in 1 round.
*)

CONSTANTS P, Q, ServerKey, Items

VARIABLES
    serverSet,
    publishedTags,
    initialTags,
    stage,
    query,
    blindR,
    blindedMsg,
    evaluatedMsg,
    result

vars == <<serverSet, publishedTags, initialTags, stage, query, blindR, blindedMsg, evaluatedMsg, result>>

RECURSIVE ModPow(_, _, _)
ModPow(base, exp, mod) ==
    IF exp = 0 THEN 1
    ELSE (base * ModPow(base, exp - 1, mod)) % mod

ValidBlinds == 1 .. (Q - 1)
ModInv(r) == CHOOSE inv \in 1 .. (Q - 1) : (r * inv) % Q = 1

HashToSubgroup(x) ==
    LET raw == (x + 2) % P
    IN (raw * raw) % P

DirectOPRF(x) == ModPow(HashToSubgroup(x), ServerKey, P)

Init ==
    /\ serverSet \in SUBSET Items
    /\ publishedTags = { DirectOPRF(s) : s \in serverSet }
    /\ initialTags = publishedTags
    /\ stage = "init"
    /\ query \in Items
    /\ blindR \in ValidBlinds
    /\ blindedMsg = 0
    /\ evaluatedMsg = 0
    /\ result = FALSE

ClientBlind ==
    /\ stage = "init"
    /\ blindedMsg' = ModPow(HashToSubgroup(query), blindR, P)
    /\ stage' = "sent"
    /\ UNCHANGED <<serverSet, publishedTags, initialTags, query, blindR, evaluatedMsg, result>>

ServerEval ==
    /\ stage = "sent"
    /\ evaluatedMsg' = ModPow(blindedMsg, ServerKey, P)
    /\ stage' = "evaluated"
    /\ UNCHANGED <<serverSet, publishedTags, initialTags, query, blindR, blindedMsg, result>>

ClientLookup ==
    /\ stage = "evaluated"
    /\ result' = (ModPow(evaluatedMsg, ModInv(blindR), P) \in publishedTags)
    /\ stage' = "done"
    /\ UNCHANGED <<serverSet, publishedTags, initialTags, query, blindR, blindedMsg, evaluatedMsg>>

Done ==
    /\ stage = "done"
    /\ UNCHANGED vars

Next == ClientBlind \/ ServerEval \/ ClientLookup \/ Done
Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ serverSet \subseteq Items
    /\ stage \in {"init", "sent", "evaluated", "done"}
    /\ result \in BOOLEAN

StatelessServer == publishedTags = initialTags

MembershipCorrectness ==
    stage = "done" => (result <=> (query \in serverSet))

BlindingPrivacy ==
    stage \in {"sent", "evaluated", "done"} =>
        \A altQ \in Items :
            \E altR \in ValidBlinds :
                ModPow(HashToSubgroup(altQ), altR, P) = blindedMsg

====
