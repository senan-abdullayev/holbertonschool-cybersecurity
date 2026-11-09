# 7-report.md — Coercion & Relay engagement report (Calder Rail)

**Prepared for:** Calder Rail security / IT operations.
**Scope:** internal AD domain `calder.local` — CALDER-DC01 (10.20.0.10, DC) and
SRV-LEGACY (10.20.0.20, member). Starting access: one unprivileged domain user
(`a.foster`). Objective: authentication-abuse (coercion + NTLM relay), not
credential theft or certificate abuse.

---

## 1. The chain — what we did, in order, and why

We began as `a.foster`, an ordinary domain user with no administrative rights
anywhere. Every capability below was earned.

**1.1 Coercion triage (which machines can be made to authenticate, and how).**
We did not assume the famous primitive would work. We tested each family and
recorded the result:

| Coercion family | CALDER-DC01 | Reason |
|---|---|---|
| MS-EFSRPC (PetitPotam) | **open** | EFSRPC reachable and unmitigated |
| MS-DFSNM (DFSCoerce) | **open** | NetrDfs reachable |
| MS-EVEN (EventLog) | **open** | eventlog interface reachable |
| MS-RPRN (PrinterBug) | **closed** | Print Spooler disabled (RPC endpoint not registered) |

Decision at this fork: the Print Spooler had been dealt with; EFSRPC had not. We
used EFSRPC. One primitive returning an error tells you only about that
primitive — the triage is the point.

**1.2 Relay triage (which relay targets survive modern defaults).** We
fingerprinted each service before spending any coerced authentication:

| Relay path | Verdict | Control responsible |
|---|---|---|
| SMB → CALDER-DC01 | closed | SMB signing **required** |
| SMB → SRV-LEGACY | **open** | SMB signing **not required** |
| SMB-origin → LDAP (DC) | closed | LDAP signing / EPA on signing-negotiated sessions |
| LDAPS / GC-LDAPS (DC) | closed | channel binding (EPA) on the TLS listener |
| WebDAV/HTTP-origin → LDAP (DC) | **open** | neither LDAP signing nor channel binding engages a non-signing, non-TLS origin |

Decision at this fork: the obvious SMB-origin relays against the DC are closed by
design. Two paths survive — SMB to the one unsigned host, and a WebDAV-origin
relay into the directory. We did not attempt a relay against the hardened DC.

**1.3 SMB relay to execution (Flag 4).** We coerced **CALDER-DC01** over EFSRPC
and relayed `CALDER-DC01$` to **SRV-LEGACY**'s unsigned SMB. Victim and target
are deliberately different hosts. `CALDER-DC01$` is a local administrator on
SRV-LEGACY, giving code execution on that host.

**1.4 WebDAV-origin relay into LDAP → RBCD (Flag 5).** The SMB-origin LDAP relay
is refused because that authentication arrives signing-negotiated; the DC's
hardening assumes exactly that. We changed the *origin protocol*: we created our
own computer account `QARELAY$` (possible because `MachineAccountQuota = 10`),
then coerced **SRV-LEGACY** over **WebDAV (HTTP)** and relayed that HTTP
authentication into the DC's LDAP. A WebDAV origin negotiates no SMB signing and
uses no TLS channel, so neither LDAP signing nor channel binding engages. The
relay wrote `msDS-AllowedToActOnBehalfOfOtherIdentity` (RBCD) on SRV-LEGACY,
delegating to `QARELAY$` — a directory write made without ever holding a
credential entitled to make it.

**1.5 S4U impersonation (Flag 6).** Using `QARELAY$`'s own password, we ran
S4U2Self + S4U2Proxy to mint a Kerberos service ticket for `cifs/srv-legacy`
**as Administrator**, and accessed SRV-LEGACY as that impersonated privileged
user.

```
a.foster (unprivileged)
  → coerce DC (EFSRPC)            → hold CALDER-DC01$ authentication
  → relay to SRV-LEGACY SMB       → local admin / code exec on SRV-LEGACY
  → create QARELAY$ (MAQ=10)
  → coerce SRV-LEGACY over WebDAV → relay to DC LDAP → RBCD on SRV-LEGACY
  → S4U as Administrator          → full control of SRV-LEGACY
```

---

## 2. Impact — in terms of access, not technique

What relaying a machine account's authentication bought, concretely: **full
administrative control of SRV-LEGACY**, reached from an account that began with
none. On that host an attacker can read any data, execute code, harvest cached
credentials and the machine's own secrets, and use it as a pivot. The domain
controller itself was **not** compromised — its hardening held throughout.

**Coerced domain controller vs coerced workstation — different categories.** A
coerced *workstation or member server* yields that machine's authentication; its
blast radius is whatever that one account is entitled to. A coerced *domain
controller* is a different class of problem: a DC's machine account is highly
privileged (it can replicate directory secrets), so relaying a DC's
authentication to a target that honours that privilege can mean domain
compromise, not single-host compromise.

**Which category this engagement fell into.** We *coerced* the DC, but we
*relayed* it to a member server where `CALDER-DC01$` was only a local admin —
so the realised impact was bounded to SRV-LEGACY, not the domain. That boundary
was our choice of target, not a protection Calder enforced. The relevant finding
is that **the DC is coercible at all**: the same coerced DC authentication, taken
to a more privileged destination, is the worse category. Treat DC coercibility as
a high-priority exposure even though this engagement's realised impact was
contained.

---

## 3. Remediation — one specific, costed fix per proven path

Each path we actually exercised is listed with the single control that closes it
and what closing it costs Calder operationally. Paths P2 and P3 are the two
relay legs; P1, P4, P5 are the enabling conditions we also proved.

**P1 — Coercion of CALDER-DC01 (MS-EFSRPC / PetitPotam open).** We made the DC
authenticate off-box over EFSRPC.
- **Specific control:** apply an **RPC filter** that blocks the MS-EFSRPC
  interface (UUID `df1941c5-fe89-4e79-bf10-463657acf44d`) from untrusted sources
  (and the same for MS-DFSNM and MS-EVEN, which also answered), plus the
  Microsoft PetitPotam/EFSRPC registry mitigation.
- **Cost:** low–moderate. Remote EFSRPC/DFSNM is rarely used by legitimate
  clients, so impact is small, but the filter set must be tested (a mis-scoped
  filter can block legitimate EFS/DFS management) and pushed via GPO/`netsh rpc filter`.

**P2 — SMB relay to SRV-LEGACY (SMB signing not required). This was an oversight.**
- **Specific control:** set **"Microsoft network server: Digitally sign
  communications (always) = Enabled"** on SRV-LEGACY, and enforce the same by GPO
  domain-wide so no host is missed again.
- **Cost:** low. Minor SMB CPU overhead; the only real work is confirming no
  legacy client depends on unsigned SMB before broad enforcement. Closes cleanly.

**P3 — WebDAV-origin relay into the DC's LDAP. This survives Calder's hardening by
design, not by mistake.** Channel binding / EPA are TLS-scoped and the "require
signing" setting only bites signing-negotiated sessions, so a WebDAV/HTTP origin
into cleartext LDAP slips past both.
- **Specific control:** set **"Domain controller: LDAP server signing
  requirements = Require signing"** *and* **LDAP channel binding = Always**, so
  the DC rejects any bind that is not integrity-protected regardless of origin —
  not only when signing was negotiated.
- **Cost:** moderate. This is the one change that needs a real compatibility test
  pass: legacy or appliance LDAP clients that bind without signing will break and
  must be fixed or exempted first. Highest operational care of the five, and the
  one that closes the surviving relay.

**P4 — Self-service computer account (`ms-DS-MachineAccountQuota = 10`) enabled the
RBCD delegate.** `a.foster` created `QARELAY$` with no special rights.
- **Specific control:** set **`ms-DS-MachineAccountQuota = 0`** domain-wide and
  delegate machine-join to a controlled group/account instead.
- **Cost:** low, but organisational: machine provisioning must move to a delegated
  join account/workflow rather than any-user self-service.

**P5 — RBCD write + S4U impersonation (the directory change and its spend).** The
relay wrote `msDS-AllowedToActOnBehalfOfOtherIdentity` on SRV-LEGACY; S4U then
impersonated Administrator.
- **Specific control:** closing P3 and P4 removes the ability to *write* this
  attribute via relay; in addition, **audit and alert on writes to
  `msDS-AllowedToActOnBehalfOfOtherIdentity`** (Directory Service Changes, event
  5136) so any future RBCD set is detected.
- **Cost:** low. One audit subcategory + a detection rule; no production impact.

The two **relay** paths require different conversations: **P2 is an oversight**
("you missed a host — require signing, done Monday"); **P3 survives correct
hardening by design** ("a control you deployed correctly does not cover this
origin — here is the layered change that does"). One of them is not a mistake
anybody made.

---

## 4. AD CS web enrollment — noted and scoped out

Calder does not appear to run an AD CS web-enrollment endpoint within the
assessed scope (no HTTP/HTTPS certificate service was present on either host). If
one exists elsewhere in the estate, flag it: **an HTTP service whose job is
issuing proof of identity is the largest surviving relay target on any network
that has one** (ESC8). It is out of scope for this engagement and should be
assessed in a dedicated one. Left here deliberately.

---

## 5. Watch item — relaying authentication back to the originating host

There is an active research line (tracked as **CVE-2025-33073** and
**CVE-2026-24294**) on relaying a host's coerced authentication **back to that
same host**, and on how that has been mitigated and then worked around again.

- **The idea:** coerce a machine to authenticate, then relay that authentication
  to a service on the *same* machine to gain code execution locally.
- **Why same-host is a special case:** Windows has specific reflection
  protections (authentication that loops back to its originating host is meant to
  be detected and rejected), which is why cross-host relay and same-host relay
  are not the same problem. The research is precisely about bypassing those
  reflection protections.
- **Why we report it rather than rely on it:** these techniques live on the patch
  cycle — they work until the next fix and are then reworked. That belongs in a
  **watch list** (awareness, detection, patch tracking), not in a methodology or
  a control you depend on. No finding in this report depends on it; we flag it so
  Calder tracks the patch state and watches for same-host relay attempts.

---

## 6. Closeout — artifacts created and reversion status

During the engagement we created three artifacts. **All three have been reverted
and the reversion verified:**

| Artifact | Purpose | Reversion status (verified) |
|---|---|---|
| ADIDNS A record `qarelay → 10.20.0.2` | single-label name for the WebDAV origin | **Removed** — deleted via LDAP; confirmed `NXDOMAIN` |
| Computer account `QARELAY$` | the RBCD delegate | **Removed** — confirmed absent (`sAMAccountName=QARELAY$` returns no object) |
| RBCD attribute on SRV-LEGACY (`msDS-AllowedToActOnBehalfOfOtherIdentity`) | delegation to `QARELAY$` | **Cleared** — confirmed empty (attribute not present on `SRV-LEGACY$`) |

The DNS record was removed with the engagement foothold. The computer account and
the RBCD attribute cannot be removed by `a.foster` (the attempt returned
`insufficientAccessRights` — correct least-privilege behaviour); they were
reverted by restoring the environment to its clean baseline, which re-provisions
the machine identities, clears the RBCD attribute, and removes the staged
account. In a production engagement the same reversion is performed by a
privileged account:

```
# clear the delegation backdoor on SRV-LEGACY
Set-ADComputer SRV-LEGACY -Clear msDS-AllowedToActOnBehalfOfOtherIdentity
# remove the staged computer account
Remove-ADComputer QARELAY
```

**Post-reversion verification (performed):** `QARELAY$` is absent from the
directory, the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute on SRV-LEGACY
is empty, the `qarelay` DNS record returns `NXDOMAIN`, and the baseline posture is
restored (SMB signing required on CALDER-DC01, not required on SRV-LEGACY). A
lingering RBCD attribute would be a standing privilege-escalation backdoor; it is
confirmed cleared.

---

## Bottom line

Calder's hardening of the domain controller is real and it held: the obvious
relays against it are closed. The exposure is (1) one member server nobody
hardened, which an attacker turns into full host compromise via SMB relay, and
(2) a WebDAV-origin relay into the directory that the DC's hardening was never
shaped to catch, which an attacker turns into RBCD and S4U. The first is a fix;
the second is a design conversation. Close both, set `MAQ=0`, reduce DC
coercibility, and scope AD CS web enrollment for the next engagement.
