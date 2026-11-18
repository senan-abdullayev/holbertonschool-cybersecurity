# 0 — Engagement Plan

**Scope:** `thornwick.local`, `corp.thornwick.local`, `ravensworth.local`. **Start:** one jack, no credential, host, or map. **Objective:** forest-root dominance of Thornwick, then Ravensworth's documents.

## Primary axis

With no credential, my first axis is the wire, not hosts: passive capture of broadcast name resolution (LLMNR/NBT-NS/mDNS) and any mis-pointed SMB. The first credential arrives *on a cadence* — a periodic auth I poison or capture for one NTLMv2: a low-privilege `corp.thornwick.local` identity and a hash to crack offline.

## Order, and why

1. **Passive / listen** (Responder analyze-only) — zero lockout risk.
2. **Unauthenticated enumeration** meanwhile: `nmap` the DCs, SMB null sessions, anonymous LDAP, RID cycling, **lockout/password policy**.
3. **Act on the first credential:** validate, map with BloodHound; the graph names the road to root (Kerberoast, AS-REP, ACL/delegation).
4. **Forest edge last:** holding the root, read the trust's *own properties* (direction, transitivity, SID-filtering) before moving; traverse only what it allows.

## Abandon signals (observable)

- Full poisoning cycles, **no authentication at my listener** → switch to contingency.
- BloodHound shows **no Kerberoastable SPN, no AS-REP-roastable account** → drop cracking, hunt ACL/delegation edges.
- Trust shows **SID-filtering enforced, no cross-forest principal granted** → edge *not traversable by injection*; find the authorised door.

## Contingency (one road is closed here)

If the listener stays silent — nothing captured, still zero credentials — I do **not** guess; I change *how* the first auth is won, credential-free:

- **Induce, don't wait.** Active Responder LLMNR/NBT-NS poisoning + mitm6 (DHCPv6/WPAD) force the periodic auth now. → a named NTLMv2 for a `corp` user.
- **Relay, don't crack.** If caught auth won't crack and SMB signing is off (`nxc` first), relay it with `ntlmrelayx` to a DC's LDAP. → an RBCD edge on a named computer — no password.
- **Enumerate if nothing induces.** Anonymous LDAP + SMB null-session RID cycling + `kerbrute` userenum build a *validated username list*; then AS-REP-roast any pre-auth-disabled account (username only). → a crackable hash for a named user.

## Discipline — lockout above all

- **No online password guessing.** I never submit a candidate password; I authenticate only with passwords I already hold (cracked offline or relayed) — lockout removed by construction, not an assumed safe rate.
- **Confirm policy first.** Read it unauthenticated (`nxc smb <dc> -u '' -p '' --pass-pol`): lockout enabled?, threshold `T`, window, reset. If unreadable, state is unknown and I authenticate against none.
- **Per-account state as a verified gate.** Before using a held credential I read its `badPwdCount`/`lockoutTime` over LDAP, proceed only if unlocked and safely below `T`, then re-read to confirm no cost. Unreadable state stops me.
- **Enumeration lockout-free by mechanism.** `kerbrute userenum` and `ntlmrelayx` submit no password — can't increment `badPwdCount`.
- **Abort.** Any unexpected `badPwdCount` rise or set `lockoutTime` → halt authentication, report.
- **Proof.** Confirm identity/position (`whoami`, dominance, cross-forest read) per milestone.

## Out of scope — what I will not touch

- **Any segment host that is not ROOT-DC (.10), CHILD-DC (.11), or RAVENSWORTH-DC (.20)** — a stray workstation, member server, or gateway is logged and left alone; scope is the three forests only.
- **Kernel/OS and service exploitation** (memory-corruption RCE, EternalBlue/SMBGhost) and **container escape** — brief-excluded; they risk crashing a DC in an identity engagement.
- **DC-destructive attacks** — ZeroLogon, event-log clearing, touching `ntds.dit`/backups: they break availability and the lab's reset.
- **Denial of service** — no flooding, resource exhaustion, lockout-inducing spray.
- **Destructive AD writes** — no deleting/disabling/password-resetting users, no production GPO/schema/trust edits. Benign writes (ACL, group, cert) are logged and removed.
- **Nothing leaves the estate** — no outbound C2; NAT adapter and host LAN untouched.
