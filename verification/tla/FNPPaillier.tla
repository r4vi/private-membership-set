---- MODULE FNPPaillier ----
EXTENDS Naturals, FiniteSets

(*
  Freedman-Nissim-Pinkas (FNP04) 1-Round Oblivious Polynomial Evaluation.
  Models exact root polynomial evaluation P_S(x) = prod_{s in S} (x - s) mod Prime
  and random masking r * P_S(x) mod Prime with r in 1..(Prime-1).
*)

CONSTANTS Prime, Items

VARIABLES
    serverSet,
    initialServerSet,
    stage,          \* "init" -> "evaluated" -> "done"
    query,
    maskR,
    maskedEval,
    result

vars == <<serverSet, initialServerSet, stage, query, maskR, maskedEval, result>>

RECURSIVE EvalRootPoly(_, _)
EvalRootPoly(S, x) ==
    IF S = {} THEN 1
    ELSE
        LET s == CHOOSE e \in S : TRUE
            diff == (x + Prime - s) % Prime
        IN (diff * EvalRootPoly(S \ {s}, x)) % Prime

Init ==
    /\ serverSet \in SUBSET Items
    /\ initialServerSet = serverSet
    /\ stage = "init"
    /\ query \in Items
    /\ maskR \in 1 .. (Prime - 1)
    /\ maskedEval = 0
    /\ result = FALSE

ServerEvaluate ==
    /\ stage = "init"
    /\ maskedEval' = (maskR * EvalRootPoly(serverSet, query)) % Prime
    /\ stage' = "evaluated"
    /\ UNCHANGED <<serverSet, initialServerSet, query, maskR, result>>

ClientDecrypt ==
    /\ stage = "evaluated"
    /\ result' = (maskedEval = 0)
    /\ stage' = "done"
    /\ UNCHANGED <<serverSet, initialServerSet, query, maskR, maskedEval>>

Done ==
    /\ stage = "done"
    /\ UNCHANGED vars

Next == ServerEvaluate \/ ClientDecrypt \/ Done
Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ serverSet \subseteq Items
    /\ stage \in {"init", "evaluated", "done"}
    /\ maskedEval \in 0 .. (Prime - 1)
    /\ result \in BOOLEAN

StatelessServer == serverSet = initialServerSet

MembershipCorrectness ==
    stage = "done" => (result <=> (query \in serverSet))

\* For any non-member, any non-zero output v in 1..(Prime-1) is achievable via some maskR,
\* proving the masked evaluation reveals zero information about serverSet.
ServerPrivacyNonMember ==
    (stage = "done" /\ query \notin serverSet) =>
        \A v \in 1 .. (Prime - 1) :
            \E r \in 1 .. (Prime - 1) :
                (r * EvalRootPoly(serverSet, query)) % Prime = v

====
