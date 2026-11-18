# 0 — Engagement Plan

**Scope:** `thornwick.local`, `corp.thornwick.local`, `ravensworth.local`. **Start:** one jack, no credential, host, or map. **Objective:** forest-root dominance of Thornwick, then the Ravensworth document set.

## Primary axis

With no credential I cannot authenticate, so my first axis is the wire, not hosts. I listen before I speak: passive capture of broadcast name resolution (LLMNR / NBT-NS / mDNS) and any mis-pointed SMB. The brief says the first credential arrives *on a cadence* — a periodic authentication I can poison or capture, yielding one NTLMv2 response: a low-privilege `corp.thornwick.local` identity and a hash to crack offline.

## Order, and why

1. **Passive / listen** (Responder analyze-only). Silent, zero lockout risk.
2. **Unauthenticated enumeration** meanwhile: `nmap` the DCs, SMB null sessions, anonymous LDAP, RID cycling, and the **lockout/password policy**.
3. **Act on the first credential:** validate, then map with BloodHound — the graph names the road to forest root (Kerberoast, AS-REP, or ACL/delegation).
4. **Forest edge last:** holding the root, read the trust's *own properties* (direction, transitivity, SID-filtering) before moving, and traverse only what it allows.

## Abandon signals (observable)

- Full poisoning cycles, **no authentication at my listener** → stop waiting, switch to contingency.
- BloodHound shows **no Kerberoastable SPN and no AS-REP-roastable account** reachable → drop cracking, hunt ACL/delegation edges.
- Trust shows **SID-filtering/quarantine enforced, no cross-forest principal granted** → edge *not traversable by injection*; find the one authorised door.

## Contingency (one road is closed here)

If the listener stays silent — nothing captured, still zero credentials — I do **not** guess passwords; I change *how* the first authentication is obtained, with credential-free primitives:

- **Induce, don't wait.** Flip Responder to active LLMNR/NBT-NS poisoning + mitm6 (DHCPv6/WPAD) to pull the periodic authentication now. → a named NTLMv2 for a `corp` user.
- **Relay, don't crack.** If I catch auth I cannot crack and SMB signing is off (`nxc` first), relay it live with `ntlmrelayx` to LDAP on a DC. → an RBCD/shadow-credential edge on a named computer — a usable auth primitive, no password.
- **Enumerate if nothing can be induced.** Anonymous LDAP + SMB null-session RID cycling + `kerbrute` AS-REQ userenum build a *validated username list* from zero; then AS-REP-roast any pre-auth-disabled account (username only). → a crackable hash for a named user.

Each branch yields a concrete object — principal, RBCD edge, or hash.

## Discipline — lockout above all

- **No online password guessing, ever.** I never submit a candidate password against any account; the only passwords I authenticate with are ones I already hold (captured-and-cracked, or relayed). Lockout is removed by construction, not by an assumed safe rate.
- **Confirm policy before anything credentialed.** First action: read it unauthenticated (`nxc smb <dc> -u '' -p '' --pass-pol`) — lockout enabled?, threshold `T`, observation window, reset. If I cannot read it, account state is unknown and I authenticate against none until I can.
- **Per-account state as a verified gate.** Before using a held credential I read that account's `badPwdCount` and `lockoutTime` over LDAP, authenticate only if unlocked and `badPwdCount` sits a safe margin below `T`, then re-read to confirm it cost nothing. Unreadable state is a stop, not a guess.
- **Enumeration lockout-free by mechanism.** `kerbrute userenum`/AS-REQ and `ntlmrelayx` submit no password, so can't increment `badPwdCount`.
- **Abort condition.** Any unexpected `badPwdCount` rise or set `lockoutTime` → halt all authentication and report.
- **Scope:** only the three named domains; nothing else.
- **No destructive actions.** Everything I write (ACL, group, cert) I log and remove; the removal goes in the report.
- **Proof:** confirm identity/position (`whoami`, dominance, cross-forest read) per milestone.
