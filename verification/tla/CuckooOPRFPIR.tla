---- MODULE CuckooOPRFPIR ----
EXTENDS Naturals, FiniteSets

(*
  Cuckoo Hashing + OPRF + 2-Slot PIR Protocol Specification (PSZ14).
  Verifies that placing every element of S into slot[h1(s)], slot[h2(s)], or
  stash (with <= 1 element per slot!) preserves exact membership via 2 PIR queries.
*)

CONSTANTS Items, NumBins

VARIABLES
    serverSet,
    table,          \* [0..(NumBins-1) -> Items \cup {"empty"}]
    initialTable,
    stash,
    stage,          \* "init" -> "queried" -> "done"
    query,
    slot1,
    slot2,
    result

vars == <<serverSet, table, initialTable, stash, stage, query, slot1, slot2, result>>

EmptySlot == 99

H1(x) == x % NumBins
H2(x) == (x + 1) % NumBins

ValidPlacement(S, T, St) ==
    /\ \A b \in 0 .. (NumBins - 1) : T[b] \in S \cup {EmptySlot}
    /\ St \subseteq S
    /\ \A s \in S : T[H1(s)] = s \/ T[H2(s)] = s \/ s \in St

Init ==
    /\ serverSet \in SUBSET Items
    /\ table \in [0 .. (NumBins - 1) -> Items \cup {EmptySlot}]
    /\ stash \in SUBSET Items
    /\ ValidPlacement(serverSet, table, stash)
    /\ initialTable = table
    /\ stage = "init"
    /\ query \in Items
    /\ slot1 = EmptySlot
    /\ slot2 = EmptySlot
    /\ result = FALSE

QueryTwoSlots ==
    /\ stage = "init"
    /\ slot1' = table[H1(query)]
    /\ slot2' = table[H2(query)]
    /\ stage' = "queried"
    /\ UNCHANGED <<serverSet, table, initialTable, stash, query, result>>

Decide ==
    /\ stage = "queried"
    /\ result' = (slot1 = query \/ slot2 = query \/ query \in stash)
    /\ stage' = "done"
    /\ UNCHANGED <<serverSet, table, initialTable, stash, query, slot1, slot2>>

Done ==
    /\ stage = "done"
    /\ UNCHANGED vars

Next == QueryTwoSlots \/ Decide \/ Done
Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ serverSet \subseteq Items
    /\ stage \in {"init", "queried", "done"}
    /\ result \in BOOLEAN

StatelessServer == table = initialTable

AtMostOnePerBin == \A b \in 0 .. (NumBins - 1) : table[b] \in serverSet \cup {EmptySlot}

MembershipCorrectness ==
    stage = "done" => (result <=> (query \in serverSet))

====
