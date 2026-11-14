# 0 — The Plan, Before You Know Where the Edges Are

## What I establish about each trust before I use it

This estate is not one network with extra hostnames; it is three organisations
(`aldermont.local`, its child `corp.aldermont.local`, and the acquired
`trentham.local`) that signed agreements at different times — the agreements are
the map, so I map before I move. For every trust I record four properties from
the live directory, not a graph, using `nltest`, `Get-ADTrust`, and `netdom`:
**direction**, **type** (parent-child vs forest), **transitivity**, and crucially
**whether it filters SIDs**. A trust is *not* usable in the direction I want when
the authority I need travels the wrong way, when it is non-transitive and I am a
hop too far, or when SID filtering will strip what I carry. A visible edge is a
hypothesis until I confirm it against the directory now.

## What has to be true before I write "crossed"

This is the paragraph that matters. I claim a crossing only when I have
authenticated as the escalated identity and read a resource that identity alone
can reach — never because a command exited zero. The child→root forge is confirmed
by reading the EA-gated `C:\RootOnly` files on ALDER-ROOT-DC. At the forest edge
the obvious move fails: the injected SID is stripped because it is foreign /
RID<1000. I diagnose that as **filtered**, not "close enough" — a claimed cross
there is an eliminatory error. Into Trentham I cross only
through the one surviving door (the leftover Aldermont universal group holding
rights on a Trentham resource), proven by reading the crown jewel.

## What I write into the directory, and proving I removed it

Every mutation in Aldermont goes through one change ledger. For each write I
record, *before touching anything*: the **domain**, the **object** (full DN), the
exact **attribute, permission, or membership** targeted, its **captured original
value**, the **new value**, and a **timestamp and purpose**. Changes are
reversible only — no new accounts, ACLs, tickets, or persistence. Rollback is not
an assertion: after the objective I restore each captured original value, then run
an **independent read-back** (a fresh `Get-ADObject` / `Get-ADGroupMember`, not a
cached result) and compare before against after. A change counts as removed
only when the after-read equals the pre-change original for every object touched,
so Aldermont can verify restoration from the diff.

## What each DC records about me

By the end, ALDER-CHILD-DC holds my krbtgt DCSync and a 4765 SIDHistory trace;
ALDER-ROOT-DC holds the forged inter-realm TGT and EA reads; and
**TRENTHAM-DC** — the acquired forest belonging to a client who did **not**
commission this engagement — logs my authentication into its resource. I touch
Trentham only as required, and disclose it.
