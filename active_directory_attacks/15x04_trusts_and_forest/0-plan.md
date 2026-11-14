# 0 — The Plan, Before You Know Where the Edges Are

## What I establish about each trust before I use it

This estate is not one network with extra hostnames; it is three organisations
(`aldermont.local`, its child `corp.aldermont.local`, and the acquired
`trentham.local`) that signed agreements at different times. Those agreements are
the map, so I map before I move. For every trust I record four properties from
the live directory — not from a graph — using `nltest /domain_trusts`,
`Get-ADTrust`, and `netdom trust`: **direction**, **type** (parent-child vs
forest), **transitivity**, and crucially **whether it filters SIDs**. A trust is
*not* usable in the direction I want when the authority I need travels the wrong
way, when it is non-transitive and I am a hop too far, or when SID filtering will
strip what I am trying to carry. A readable object or a visible edge is a
hypothesis until I confirm its condition against the directory as it stands now.

## What has to be true before I write "crossed"

This is the paragraph that matters. I will claim a boundary was crossed only when
I have authenticated as the escalated identity and read a resource that identity
alone can reach — not because a command exited zero. The child→root ExtraSids
forge is confirmed by reading the EA-gated `C:\RootOnly` files on ALDER-ROOT-DC.
At the forest edge the obvious move fails: the same injected SID is stripped
because it is foreign / RID<1000. I will diagnose that as **filtered**, not
"close enough" — a claimed cross there is an eliminatory, damaging error. Into
Trentham I cross only through the one surviving door (the leftover Aldermont
universal group with rights on a Trentham resource), proven by reading the crown
jewel, never by a false SID-history claim.

## What I write, and proving I removed it

Any change into Aldermont's directory — a group membership I add to reach the
door — is minimal and reversible. I log the before-state, make the change, and
show the matching removal plus a final `Get-ADGroupMember` confirming the object
is clean. No tickets, accounts, or persistence are left behind.

## What each DC records about me

By the end, ALDER-CHILD-DC holds my DCSync of its krbtgt and a 4765 SIDHistory
trace; ALDER-ROOT-DC holds the forged inter-realm TGT use and EA-level reads; and
**TRENTHAM-DC** — the acquired forest belonging to a client who did **not**
commission this engagement — logs my authentication into its resource. That last
fact drives the scoping conversation: I touch Trentham only as the lesson
requires, and disclose it.
