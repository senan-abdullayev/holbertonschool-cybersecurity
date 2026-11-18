# 0 — Engagement Plan

**Scope:** `thornwick.local`, `corp.thornwick.local`, `ravensworth.local`. **Start:** one jack, no credential, no host, no map. **Objective:** forest-root dominance of Thornwick, then the Ravensworth document set.

## Primary axis

With no credential I cannot authenticate, so my first axis is the wire, not hosts. I listen before I speak: passive capture of broadcast name-resolution traffic (LLMNR / NBT-NS / mDNS) and any mis-pointed SMB on the segment. The brief says the first credential arrives *on a cadence, not on demand* — a periodic authentication I can poison or capture. I expect one NTLMv2 response: a low-privilege `corp.thornwick.local` identity and a hash to crack offline — my pivot to authenticated enumerator.

## Order, and why

1. **Passive / listen** (tcpdump, Responder analyze-only). Silent, zero lockout risk.
2. **Unauthenticated enumeration** while I wait: `nmap` the DCs, SMB null sessions, anonymous LDAP, RID cycling, and the **lockout/password policy** before I ever guess.
3. **Act on the first credential:** validate, then map with BloodHound/SharpHound. Let the graph name the road to forest root — Kerberoast, AS-REP, or an ACL/delegation edge.
4. **Forest edge last:** holding the root, read the Thornwick↔Ravensworth trust's *own properties* (direction, transitivity, SID-filtering/quarantine) before moving, and traverse only what it permits.

Safest first, destructive-last.

## Abandon signals (observable)

- Full poisoning cycles across the cadence, **no authentication reaching my listener** → stop waiting, switch to the contingency below.
- BloodHound shows **no Kerberoastable SPN and no AS-REP-roastable account** reachable → drop offline cracking, hunt ACL/delegation edges.
- Trust shows **SID-filtering/quarantine enforced, no granted cross-forest principal** → the edge is *not traversable by injection*; find the one authorised door.

## Contingency (one road is closed here)

The failure I plan for is the listener staying silent — nothing captured, still zero credentials. I do **not** guess passwords; I change *how* the first authentication is obtained, using only credential-free primitives:

- **Induce, don't wait.** Flip Responder to active LLMNR/NBT-NS poisoning and add mitm6 (DHCPv6 + WPAD) to pull the periodic authentication to me now. → a named NTLMv2 for a `corp` user.
- **Relay, don't crack.** If I catch auth I cannot crack and SMB signing is off (`nxc` check first), relay it live with `ntlmrelayx` to LDAP on a DC. → an RBCD/shadow-credential edge on a named computer — a usable auth primitive, no password.
- **Enumerate if nothing can be induced.** Anonymous LDAP + SMB null-session RID cycling + `kerbrute` AS-REQ userenum build a *validated username list* from zero; then AS-REP-roast any pre-auth-disabled account (username only). → a crackable hash for a named user.

Each branch yields a specific object — a principal, an RBCD edge, or a hash — feeding step-3 mapping.

## Discipline — lockout above all

- **Read the policy before any authentication attempt.** First action: retrieve the lockout policy unauthenticated (`nxc smb <dc> -u '' -p '' --pass-pol`) — **threshold**, **observation window**, **reset**. No credentialed probe until I have those three numbers.
- **Separate safe enumeration from risky guessing.** Username existence via Kerberos pre-auth (`kerbrute userenum`) does **not** increment `badPwdCount` and cannot lock an account; only a *password* attempt counts against the threshold.
- **Hard budget.** If I test a password: cap `threshold − 2` per account per window, one at a time, timestamp-logged, spaced beyond reset. Offline cracking always preferred.
- **Scope:** only the three named domains; nothing else on the segment.
- **No destructive actions.** Everything I write (an ACL, a group, a cert) I log and remove; the removal goes in the report.
- **Proof over output:** I confirm identity/position (`whoami`, dominance, the cross-forest read) at each milestone, not a zero exit.
