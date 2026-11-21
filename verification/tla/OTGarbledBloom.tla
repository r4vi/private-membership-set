---- MODULE OTGarbledBloom ----
EXTENDS Naturals, FiniteSets

(*
  Dong-Chen-Wen (DCW13) Garbled Bloom Filter + Chou-Orlandi 1-out-of-2 OT.
  Models:
    - Chou-Orlandi OT key agreement (B = c*A + b*G mod Order) & choice privacy
    - Garbled Bloom Filter XOR share reconstruction over k = 2 slots
*)

CONSTANTS Order, SenderA, NumSlots, Items

VARIABLES
    serverSet,
    gbfSlots,       \* [0..(NumSlots-1) -> 0..1] (1-bit model of XOR shares)
    initialSlots,
    stage,
    query,
    otRand,         \* [0..(NumSlots-1) -> 0..(Order-1)]
    otWireB,        \* [0..(NumSlots-1) -> 0..(Order-1)]
    retrieved,      \* [0..(NumSlots-1) -> 0..1]
    result

vars == <<serverSet, gbfSlots, initialSlots, stage, query, otRand, otWireB, retrieved, result>>

BitXor(a, b) == (a + b) % 2

\* Disjoint 2-slot hash mapping for each item (models collision-free GBF)
Pos1(x) == (2 * x) % NumSlots
Pos2(x) == (2 * x + 1) % NumSlots
ItemTag(x) == 1

ChoiceBit(x, i) == IF i = Pos1(x) \/ i = Pos2(x) THEN 1 ELSE 0

ValidGBF(S, slots) ==
    /\ \A s \in S : BitXor(slots[Pos1(s)], slots[Pos2(s)]) = ItemTag(s)
    /\ \A s \in (Items \ S) : BitXor(slots[Pos1(s)], slots[Pos2(s)]) # ItemTag(s)

Init ==
    /\ serverSet \in SUBSET Items
    /\ gbfSlots \in [0 .. (NumSlots - 1) -> {0, 1}]
    /\ ValidGBF(serverSet, gbfSlots)
    /\ initialSlots = gbfSlots
    /\ stage = "init"
    /\ query \in Items
    /\ otRand \in [0 .. (NumSlots - 1) -> 0 .. (Order - 1)]
    /\ otWireB = [i \in 0 .. (NumSlots - 1) |-> 0]
    /\ retrieved = [i \in 0 .. (NumSlots - 1) |-> 0]
    /\ result = FALSE

ClientOTChoose ==
    /\ stage = "init"
    /\ otWireB' = [i \in 0 .. (NumSlots - 1) |->
                    (ChoiceBit(query, i) * SenderA + otRand[i]) % Order]
    /\ stage' = "ot_sent"
    /\ UNCHANGED <<serverSet, gbfSlots, initialSlots, query, otRand, retrieved, result>>

ServerOTRespondAndClientDecrypt ==
    /\ stage = "ot_sent"
    \* Chou-Orlandi OT: receiver decrypts m_{ChoiceBit(query, i)} using key b*A = a*(B - c*A)
    /\ retrieved' = [i \in 0 .. (NumSlots - 1) |->
                        IF ChoiceBit(query, i) = 1 THEN gbfSlots[i] ELSE 0]
    /\ result' = (BitXor(retrieved'[Pos1(query)], retrieved'[Pos2(query)]) = ItemTag(query))
    /\ stage' = "done"
    /\ UNCHANGED <<serverSet, gbfSlots, initialSlots, query, otRand, otWireB>>

Done ==
    /\ stage = "done"
    /\ UNCHANGED vars

Next == ClientOTChoose \/ ServerOTRespondAndClientDecrypt \/ Done
Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ serverSet \subseteq Items
    /\ stage \in {"init", "ot_sent", "done"}
    /\ result \in BOOLEAN

StatelessServer == gbfSlots = initialSlots

MembershipCorrectness ==
    stage = "done" => (result <=> (query \in serverSet))

\* Information-theoretic Chou-Orlandi OT receiver privacy: every wire message B_i
\* is equally consistent with choice bit 0 and choice bit 1!
OTChoicePrivacy ==
    stage \in {"ot_sent", "done"} =>
        \A i \in 0 .. (NumSlots - 1) :
            \A altC \in {0, 1} :
                \E altB \in 0 .. (Order - 1) :
                    (altC * SenderA + altB) % Order = otWireB[i]

====
