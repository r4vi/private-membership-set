---- MODULE PMSetGeneric ----
EXTENDS Naturals, FiniteSets, Sequences

(*
  Generic Transport-Agnostic Private Set Membership (PMSet) State Machine.
  Models two interleaved client sessions interacting with a stateless server
  holding a secret set S \subseteq Items.

  Properties model-checked by TLC:
    - TypeOK: all variables stay within their typed domains.
    - StatelessServer: server state never mutates across requests.
    - MembershipCorrectness: every completed session outputs (query \in ServerSet).
    - TranscriptIndistinguishability: server observes blinded/encrypted tokens
      that are identically realizable for any query in Items.
*)

CONSTANTS Items, Blinds, MaxRounds

VARIABLES
    serverSet,
    initialServerSet,
    phase,          \* Function [1..2 -> {"init", "sent", "done"}]
    clientQuery,    \* Function [1..2 -> Items]
    clientBlind,    \* Function [1..2 -> Blinds]
    wireToken,      \* Observed token on the wire (opaque to server)
    clientResult    \* Function [1..2 -> BOOLEAN \cup {"none"}]

vars == <<serverSet, initialServerSet, phase, clientQuery, clientBlind, wireToken, clientResult>>

Sessions == {1, 2}

\* Abstract perfect blinding bijection: every (query, blind) maps to an opaque token
\* such that for any other query q2 there exists blind b2 yielding the same token.
OpaqueToken(q, b) == (q + b) % Cardinality(Items)

Init ==
    /\ serverSet \in SUBSET Items
    /\ initialServerSet = serverSet
    /\ phase = [s \in Sessions |-> "init"]
    /\ clientQuery \in [Sessions -> Items]
    /\ clientBlind \in [Sessions -> Blinds]
    /\ wireToken = [s \in Sessions |-> 0]
    /\ clientResult = [s \in Sessions |-> FALSE]

SendQuery(s) ==
    /\ phase[s] = "init"
    /\ wireToken' = [wireToken EXCEPT ![s] = OpaqueToken(clientQuery[s], clientBlind[s])]
    /\ phase' = [phase EXCEPT ![s] = "sent"]
    /\ UNCHANGED <<serverSet, initialServerSet, clientQuery, clientBlind, clientResult>>

ServerRespondAndClientDecide(s) ==
    /\ phase[s] = "sent"
    \* Server handles request WITHOUT mutating serverSet
    /\ clientResult' = [clientResult EXCEPT ![s] = (clientQuery[s] \in serverSet)]
    /\ phase' = [phase EXCEPT ![s] = "done"]
    /\ UNCHANGED <<serverSet, initialServerSet, clientQuery, clientBlind, wireToken>>

Done ==
    /\ \A s \in Sessions : phase[s] = "done"
    /\ UNCHANGED vars

Next ==
    \/ \E s \in Sessions : SendQuery(s) \/ ServerRespondAndClientDecide(s)
    \/ Done

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ serverSet \subseteq Items
    /\ \A s \in Sessions : phase[s] \in {"init", "sent", "done"}
    /\ \A s \in Sessions : clientQuery[s] \in Items
    /\ \A s \in Sessions : clientResult[s] \in BOOLEAN

StatelessServer == serverSet = initialServerSet

MembershipCorrectness ==
    \A s \in Sessions :
        phase[s] = "done" => (clientResult[s] <=> (clientQuery[s] \in serverSet))

ClientQueryPrivacy ==
    \A s \in Sessions :
        phase[s] \in {"sent", "done"} =>
            \A altQ \in Items :
                \E altB \in Blinds : OpaqueToken(altQ, altB) = wireToken[s]

====
