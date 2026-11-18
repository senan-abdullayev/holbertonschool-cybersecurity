# 0 — Engagement Plan

**Scope:** `thornwick.local`, `corp.thornwick.local`, `ravensworth.local`. **Start:** one jack, no credential, no host, no map. **Objective:** forest-root dominance of Thornwick, then the document set in the acquired Ravensworth forest.

## Primary axis

With no credential I cannot authenticate, so my first axis is the wire, not the hosts. I listen before I speak: passive capture of broadcast name-resolution traffic (LLMNR / NBT-NS / mDNS) and any SMB a mis-pointed client throws at the segment. The brief says the first credential arrives *on a cadence, not on demand* — a periodic authentication I can poison or capture. I expect one NTLMv2 response: a username and a hash to crack offline, i.e. a low-privilege identity in `corp.thornwick.local` — my pivot from outsider to authenticated enumerator.

## Order, and why

1. **Passive / listen** (tcpdump, Responder analyze-only first). Free, silent, zero lockout risk.
2. **Unauthenticated enumeration** while I wait: `nmap` the three DCs, SMB null sessions, anonymous LDAP, RID cycling, and — critically — read the **lockout and password policy** so I know my budget before I ever guess.
3. **Act on the first credential:** validate it, then map with BloodHound/SharpHound. Let the graph, not habit, name the road to forest root — Kerberoast, AS-REP, or an ACL/delegation edge, whichever this estate leaves open.
4. **Forest edge last:** holding the root, read the Thornwick↔Ravensworth trust's *own properties* (direction, transitivity, SID-filtering/quarantine) before moving at it, and traverse only what it permits.

Safest first, destructive last.

## Abandon signals (observable, not vibes)

- After several full poisoning cycles across the cadence with **no authentication reaching my listener**, I stop waiting and pivot to enumeration-derived usernames.
- If BloodHound shows **no Kerberoastable SPN and no AS-REP-roastable account** reachable from my identity, I drop offline cracking and hunt ACL/delegation edges.
- If the trust shows **SID-filtering/quarantine enforced with no granted cross-forest principal**, I treat the forest edge as *not traversable by injection* and look for the one legitimately-authorised door.

## Contingency (one road is closed here)

If the listener yields nothing, I do **not** fall back to password guessing — that is the one action that ends this engagement. I widen the *no-password* surface instead: AS-REP-roasting (needs no password), NTLM relay of the captured authentication to a target that permits it, and any credential leaked in SYSVOL/GPP, shares, or LDAP attributes. If offline cracking of the captured hash fails, the BloodHound graph edges — not guessing — become the path to the root.

## Discipline — account lockout above all

- **Read the policy before any authentication attempt.** First action on the segment is to retrieve the lockout policy unauthenticated (SMB null / anonymous LDAP / `nxc smb <dc> -u '' -p '' --pass-pol`): **threshold**, **observation window**, **reset** duration. No credentialed probe goes out until I have those three numbers.
- **Separate safe enumeration from risky guessing.** Username existence is checked with Kerberos pre-auth (`kerbrute userenum` / AS-REQ), which does **not** increment `badPwdCount` and cannot lock an account. Only a *password* attempt counts against the threshold.
- **Hard budget.** If I ever test a password: cap `threshold − 2` per account per observation window, one account at a time, timestamp-logged, spaced beyond the reset window. Capture-and-crack offline always preferred over any online attempt.
- **Scope is the contract:** only the three named domains; anything else on the segment is untouched.
- **No destructive actions.** Everything I write (an ACL, a group, a cert) I log and remove; the removal goes in the report.
- **Proof over output:** I confirm identity/position (`whoami`, dominance, the cross-forest read) at each milestone, not a zero exit code.
