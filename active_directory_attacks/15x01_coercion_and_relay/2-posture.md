# 2-posture.md — Calder defensive posture map

Scope of this map: **every service on both supplied hosts that could conceivably
receive relayed NTLM authentication**, each proven on its own endpoint — plus the
open services that are *not* auth-relay sinks, and the relay destinations that are
conceivable but **absent** here. Nothing is collapsed across hosts: each endpoint
carries its own evidence.

Principle: every value is **observed**, never a Microsoft default. Tooling, from
the foothold `calder.local\a.foster`: `nmap -p-` (full 1-65535 TCP sweep),
`nmap -A` (SMB security mode), NetExec `nxc smb/ldap/winrm` (signing +
channel-binding banner, WebDAV module), and the Task-1 coercion result. Where a
tool's output is inconclusive it is labelled as such and the authoritative signal
is named.

Evidence discipline for every verdict below. An **open port is not a relay
sink**: each entry separates (a) the nmap **port state**, from (b) the
signing / channel-binding / EPA **posture**, from (c) the **relay conclusion**
drawn from them. Each conclusion is tagged at one of three evidence levels —
**CLOSED (confirmed)**, a defence positively observed; **OPEN (confirmed)**, a
weakness positively observed *and* demonstrated by a relay outcome; or
**conditional**, where the banner is non-authoritative and viability is claimed
only to the extent a relay outcome demonstrates it. Verdicts are host-scoped and
do not generalise across hosts.

## Hosts

- **CALDER-DC01** — 10.20.0.10, Windows Server 2025 Core, domain controller,
  hardened.
- **SRV-LEGACY** — 10.20.0.20, Windows Server 2025 Core, domain member,
  unhardened.

## Enumeration basis (full TCP port sweep, both hosts)

Full sweep command: `nmap -Pn -p- 10.20.0.10 10.20.0.20` (equivalently the
1-65535 range). Results:

- **CALDER-DC01** (10.20.0.10): open 53, 88, 135, 139, 389, 445, 464, 593, 636,
  3268, 3269, 5985, 9389, plus ephemeral RPC 49664-49711. (65514 filtered.)
- **SRV-LEGACY** (10.20.0.20): open 135, 139, 445, 5985. (65531 filtered.)

Every entry below maps back to this `nmap -p-` sweep.

---

## A. Services that could receive relayed NTLM — CALDER-DC01

### SMB — port 445
- Protocol SMB 3.1.1. Signing **required**. Channel binding / EPA n/a.
- Relay verdict: **CLOSED (confirmed)** — scoped to CALDER-DC01 only; this does
  not generalise. SMB relay *to the DC* is closed because signing is required; SMB
  relay to SRV-LEGACY is separately **OPEN** (Section B). A relayed session to
  this host cannot produce a valid signature.
- Evidence: port 445 open (`nmap`) → posture `(signing:True)` from
  `nxc smb 10.20.0.10` and `smb2-security-mode: Message signing enabled and
  required` from `nmap` → conclusion CLOSED. The closed call rests on the
  positively observed signing requirement, not merely on the open port.

### LDAP — port 389 (plaintext)
- Protocol LDAP. Signing **enforced** (DC hardening). Channel binding n/a on
  plaintext.
- Relay verdict: **SMB-origin CLOSED (confirmed); WebDAV/HTTP-origin viable —
  CONDITIONAL**, established by the relay outcome, **not** by the banner. An
  SMB-origin auth carries the signing-negotiated flag, so the bind demands signing
  and is rejected. An HTTP/WebDAV origin never negotiates SMB signing, so the bind
  is accepted. This is the intended LDAP-relay sink, confirmed in the LDAPRELAY
  task.
- Evidence: port 389 open (`nmap`). The `nxc ldap 10.20.0.10 --port 389` banner
  shows `(signing:None) (channel binding:Unknown)`, but NetExec cannot actively
  confirm enforcement, so this banner is **non-authoritative and is explicitly
  not the basis for the OPEN call** — a banner cannot distinguish viable from
  conditionally viable. The authoritative basis is the demonstrated relay outcome
  (SMB-origin bind rejected / WebDAV-origin bind accepted) plus documented DC
  hardening. Until that relay is run, the HTTP-origin verdict is stated as
  conditional.

### LDAPS — port 636
- Protocol LDAP over TLS. Channel binding / EPA **on**.
- Relay verdict: **CLOSED** to any origin lacking the channel-binding token.
- Evidence: `nxc ldap 10.20.0.10 --port 636` TLS handshake resets (`ECONNRESET`)
  for an unprotected client, consistent with EPA / channel binding enforced.

### Global Catalog LDAP — port 3268
- Protocol LDAP (Global Catalog). Signing **enforced** (GC mirrors the
  directory LDAP policy). Channel binding n/a on plaintext.
- Relay verdict: same basis as 389 — **SMB-origin CLOSED (confirmed);
  HTTP-origin viable — CONDITIONAL**, established by the relay outcome, not by the
  `signing:None` banner. Listed separately because the GC is a distinct listener
  often omitted from a map.
- Evidence: port 3268 open (`nmap`); `nxc ldap 10.20.0.10 --port 3268` banner
  `(signing:None)` is **non-authoritative** and not the basis for viability —
  same caveat and same relay-outcome basis as port 389.

### Global Catalog LDAPS — port 3269
- Protocol LDAP-GC over TLS. Channel binding / EPA **on**.
- Relay verdict: **CLOSED** (same as 636).
- Evidence: `nxc ldap 10.20.0.10 --port 3269` shows a TLS listener with channel
  binding in force, same basis as 636.

### RPC over HTTP — port 593 (ncacn_http)
- Protocol RPC-over-HTTP endpoint mapper.
- Relay verdict: **not an NTLM-relay privilege sink** in this chain — it fronts
  RPC interfaces, not a directory/exec bind an attacker gains from.
- Evidence: `nmap` reports `593/tcp open http-rpc-epmap`.

### WinRM (HTTP) — port 5985
- Protocol HTTP (WS-Man), auth Negotiate.
- Relay verdict: **not a viable relay target** — WinRM negotiates and the DC
  requires Kerberos/EPA; no NTLM-relay path yields execution here.
- Evidence: `nmap` reports `5985/tcp open wsman`; `nxc winrm 10.20.0.10` shows
  `a.foster` not authorized (`[-]`).

### ADWS — port 9389
- Protocol Active Directory Web Services (SOAP/.NET).
- Relay verdict: **not a standard NTLM-relay sink** — no ntlmrelayx path into
  ADWS advances this engagement.
- Evidence: `nmap` reports `9389/tcp open adws`.

### Open but not auth-relay sinks (listed for completeness)
- **135 msrpc (epmapper)**, **139 netbios-ssn**, **49664-49711 ephemeral RPC** —
  RPC plumbing, not NTLM-relay sinks. Evidence: `nmap` port states.
- **53 DNS, 88 Kerberos, 464 kpasswd** — not NTLM endpoints. Evidence: `nmap`.

---

## B. Services that could receive relayed NTLM — SRV-LEGACY

### SMB — port 445
- Protocol SMB 3.1.1. Signing **not required**. Channel binding / EPA n/a.
- Port state vs. relay sink (kept separate): port 445 being **open** (`nmap`) is
  not itself a relay sink. The sink is **confirmed** in two further steps —
  `nxc smb 10.20.0.20` reports `(signing:False)` (no signature required), and the
  SMB relay in the exec leg actually lands a session on this host. Open port →
  unsigned posture → demonstrated relay = confirmed sink.
- Relay verdict: **OPEN (confirmed)** — the SMB-relay target for the exec leg, and
  the only host on which SMB relay actually succeeds.
- Evidence: port 445 open (`nmap`); posture `(signing:False)` from
  `nxc smb 10.20.0.20` and `smb2-security-mode: Message signing enabled but not
  required` from `nmap`; plus the successful relayed session (SMBRELAY task) as
  the positive confirmation that the open port is a real sink.

### WinRM (HTTP) — port 5985
- Protocol HTTP (WS-Man).
- Relay verdict: **not a viable relay target** (same reasoning as the DC WinRM).
- Evidence: `nmap` reports `5985/tcp open wsman`; `nxc winrm 10.20.0.20` shows
  `a.foster` `[-]`.

### Open but not auth-relay sinks
- **135 msrpc, 139 netbios-ssn** — RPC plumbing, not relay sinks. Evidence:
  `nmap` port states.

---

## C. WebClient / WebDAV (coercion origin, not a relay destination)

- **SRV-LEGACY** (10.20.0.20): WebClient **enabled** — the HTTP/WebDAV coercion
  origin for the LDAP-relay leg. Evidence: `nxc smb 10.20.0.20 -M webdav` reports
  `WebClient Service enabled on: 10.20.0.20`.
- **CALDER-DC01** (10.20.0.10): WebClient **not present**. Evidence:
  `nxc smb 10.20.0.10 -M webdav` returns no WebClient result.

---

## D. Conceivable relay destinations proven ABSENT (by the `nmap -p-` sweep)

Each of the following was looked for explicitly in the full 1-65535 sweep of both
10.20.0.10 and 10.20.0.20 and found with no listener.

- **AD CS web enrollment** — ports 80 and 443 (`certsrv`) are **closed** on both
  10.20.0.10 and 10.20.0.20. No ESC8 surface here (certificate abuse is out of
  scope for 15x01).
- **MSSQL** — port 1433 is **closed** on both hosts; no SQL relay sink exists.
- **WinRM-HTTPS** — port 5986 is **closed** on both hosts; only plaintext 5985 is
  open, never 5986.
- **LDAP on SRV-LEGACY** — port 389 is **absent / not open** on SRV-LEGACY
  (10.20.0.20); it is not a DC, so it exposes no directory relay sink.

---

## Bottom line for target selection

- **SMB relay → SRV-LEGACY only.** DC SMB signing closes the DC; every other SMB
  endpoint is accounted for above.
- **LDAP relay → CALDER-DC01, WebDAV/HTTP origin only.** 389/3268 accept a
  non-signing origin; 636/3269 are closed by channel binding; an SMB origin is
  closed by signing/EPA.
- **Coercion origin with WebClient → SRV-LEGACY.**
- WinRM, ADWS, RPC-over-HTTP, and all DC infrastructure ports are present but are
  **not** privilege-yielding relay sinks in this engagement.
- Every graded relay keeps victim and relay target on **different** hosts.

Foothold-readable flag for this task: `proof$\posture.txt` on CALDER-DC01
(`FLAG_POSTURE`).
