# 0 — Engagement Plan

**Client:** Thornwick Aerospace · **Scope:** `thornwick.local`, `corp.thornwick.local`, `ravensworth.local`
**Starting position:** one jack on the estate segment, no credential, no host, no map.
**Objective:** forest-root dominance of Thornwick, then the document set in the acquired Ravensworth forest.

## Primary axis

With no credential, I cannot authenticate to anything, so my first axis is the wire, not the hosts. I will listen before I speak: passive capture of broadcast name-resolution traffic (LLMNR / NBT-NS / mDNS) and any SMB that a mis-pointed client throws at the segment. The brief says the first credential arrives *on a cadence, not on demand* — that reads like a periodic authentication I can poison or capture. I expect this to yield one NTLMv2 response: a username and a hash I can crack offline, i.e. a single low-privilege identity in `corp.thornwick.local`, the stated entry surface. That identity is the pivot from "outsider on a segment" to "authenticated enumerator."

## Order, and why

1. **Passive / listen** (tcpdump, Responder in analyze-only first). Free, silent, and it may hand me the credential with zero risk of lockout.
2. **Unauthenticated enumeration** while I wait: `nmap` the three DCs, SMB null sessions, anonymous LDAP, RID cycling, and — critically — read the **account-lockout and password policy** so I know my budget before I ever guess.
3. **Act on the first credential:** validate it, then map with BloodHound/SharpHound. Let the graph, not habit, name the road to forest root — Kerberoast, AS-REP, or an ACL/delegation edge, whichever this estate actually leaves open.
4. **Forest edge last:** once I hold the root, read the Thornwick↔Ravensworth trust's *own properties* (direction, transitivity, SID-filtering/quarantine) before I move at it, and only traverse what the boundary genuinely permits.

This order is cheapest-and-safest first, destructive-potential last.

## Abandon signals (observable, not vibes)

- If after several full poisoning cycles across the expected cadence **no authentication reaches my listener**, I stop waiting and pivot to enumeration-derived usernames.
- If BloodHound shows **no Kerberoastable SPN and no AS-REP-roastable account** reachable from my identity, I drop the offline-cracking road and hunt ACL/delegation edges instead.
- If I read the trust and see **SID-filtering/quarantine enforced with no granted cross-forest principal**, I treat the forest edge as *not traversable by injection* and look for the one legitimately-authorised door rather than forcing it.

## Contingency (one road is closed here)

If the listener yields nothing, my fallback is a **single, policy-aware guess**: usernames from enumeration against one common password, one attempt per account, well under the lockout threshold, spaced beyond the observation window — never a blind spray. If offline cracking fails, the graph edges become the primary path to the root.

## Discipline

- **No lockouts:** read the lockout policy *first*; count every authentication attempt per account against it; prefer capture and offline cracking over online guessing; long delays, low volume.
- **Scope is the contract:** only the three named domains. Anything else on the segment is untouched, whatever I find.
- **No destructive actions.** Everything I write into the estate (an ACL, a group membership, a cert) I log and remove, and the removal goes in the report.
- **Proof over output:** I confirm identity/position (`whoami`, dominance, the cross-forest read) at each milestone, not a zero exit code.
