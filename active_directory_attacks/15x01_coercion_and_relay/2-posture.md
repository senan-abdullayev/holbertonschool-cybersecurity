# 2-posture.md — Calder defensive posture map

Scope of this map: **every service on both supplied hosts that could conceivably
receive relayed NTLM authentication**, each proven on its own endpoint — plus the
open services that are *not* auth-relay sinks, and the relay destinations that are
conceivable but **absent** here. Nothing is collapsed across hosts: each endpoint
carries its own evidence.

Principle: every value is **observed**, never a Microsoft default. Tools, from the
foothold `calder.local\a.foster`: `nmap -p-` (full service enumeration),
`nmap -A` (SMB security mode), NetExec `nxc smb/ldap/winrm` (signing +
channel-binding banner, WebDAV module), and the Task-1 coercion result. Where a
tool's output is inconclusive it is labelled as such and the authoritative signal
is named.

## Hosts

- **CALDER-DC01** — `10.20.0.10`, Windows Server 2022 Build 20348, domain
  controller, hardened.
- **SRV-LEGACY** — `10.20.0.20`, Windows Server 2022 Build 20348, domain member,
  unhardened.

## Enumeration basis (full TCP sweep, both hosts)

`nmap -Pn -p- 10.20.0.10 10.20.0.20`:

- **CALDER-DC01:** 53, 88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269, 5985,
  9389, + ephemeral RPC (49664-49711). (65514 filtered.)
- **SRV-LEGACY:** 135, 139, 445, 5985. (65531 filtered.)

Every entry below maps back to this sweep.

---

## A. Services that could receive relayed NTLM — CALDER-DC01

### SMB / 445
- Protocol SMB 3.1.1. Signing **required**. CB/EPA n/a.
- Relay verdict: **CLOSED** (relayed session cannot sign).
- Evidence: `nxc smb 10.20.0.10` → `(signing:True)`; nmap
  `smb2-security-mode: Message signing enabled and required`.

### LDAP / 389 (plain)
- Protocol LDAP. Signing: **enforced** (per DC hardening). CB: n/a on plaintext.
- Relay verdict: **SMB-origin CLOSED, WebDAV/HTTP-origin OPEN.** SMB-origin auth
  carries the signing-negotiated flag → bind demands signing → rejected. An
  HTTP/WebDAV origin does not negotiate SMB signing → the bind is accepted. This
  is the intended LDAP-relay sink.
- Evidence: `nxc ldap --port 389` banner reports `(signing:None)
  (channel binding:Unknown)` — **NetExec cannot actively confirm enforcement, so
  this banner is non-authoritative**; the authoritative proof is the relay
  outcome in the LDAPRELAY task (SMB-origin rejected / WebDAV-origin accepted)
  plus the documented DC hardening.

### LDAPS / 636
- Protocol LDAP over TLS. CB / EPA: **on**.
- Relay verdict: **CLOSED to any origin lacking the channel-binding token.**
- Evidence: `nxc ldap --port 636` → TLS handshake `ECONNRESET` for an
  unprotected client, consistent with EPA/channel binding enforced.

### Global Catalog LDAP / 3268
- Protocol LDAP (GC). Signing: **enforced** (GC mirrors the directory's LDAP
  policy). CB n/a on plaintext.
- Relay verdict: same as 389 — **SMB-origin CLOSED, HTTP-origin OPEN**. Listed
  separately because the GC is a distinct listener often left out of a map.
- Evidence: `nxc ldap --port 3268` banner `(signing:None)
  (channel binding:No TLS cert)` — non-authoritative, same caveat as 389.

### Global Catalog LDAPS / 3269
- Protocol LDAP-GC over TLS. CB / EPA: **on**.
- Relay verdict: **CLOSED** (same as 636).
- Evidence: `nxc ldap --port 3269` reports a TLS listener; channel binding in
  force, same basis as 636.

### RPC over HTTP / 593 (ncacn_http)
- Protocol RPC-over-HTTP endpoint mapper.
- Relay verdict: **not an NTLM-relay privilege sink** in this chain — it fronts
  RPC interfaces, not a directory/exec bind an attacker gains from.
- Evidence: nmap `593/tcp open http-rpc-epmap`.

### WinRM / 5985
- Protocol HTTP (WS-Man). Auth Negotiate.
- Relay verdict: **not a viable relay target** — WinRM negotiates and the DC
  requires Kerberos/EPA for it; no NTLM-relay path yields execution here.
- Evidence: nmap `5985/tcp open wsman`; `nxc winrm 10.20.0.10` →
  `a.foster` not authorized (`[-]`), i.e. no foothold WinRM access either.

### ADWS / 9389
- Protocol Active Directory Web Services (SOAP/.NET).
- Relay verdict: **not a standard NTLM-relay sink** — no ntlmrelayx path into
  ADWS advances this engagement.
- Evidence: nmap `9389/tcp open adws`.

### Open-but-not-auth-relay services (listed for completeness)
- **135 msrpc (epmapper)**, **139 netbios-ssn**, **49664-49711 ephemeral RPC** —
  RPC plumbing, not NTLM-relay sinks. Evidence: nmap port states.
- **53 DNS, 88 Kerberos, 464 kpasswd** — not NTLM endpoints. Evidence: nmap.

---

## B. Services that could receive relayed NTLM — SRV-LEGACY

### SMB / 445
- Protocol SMB 3.1.1. Signing: **not required**. CB/EPA n/a.
- Relay verdict: **OPEN** — this is the SMB-relay target for the exec leg.
- Evidence: `nxc smb 10.20.0.20` → `(signing:False)`; nmap
  `smb2-security-mode: Message signing enabled but not required`.

### WinRM / 5985
- Protocol HTTP (WS-Man).
- Relay verdict: **not a viable relay target** (same reasoning as the DC's WinRM).
- Evidence: nmap `5985/tcp open wsman`; `nxc winrm 10.20.0.20` → `a.foster` `[-]`.

### Open-but-not-auth-relay services
- **135 msrpc, 139 netbios-ssn** — RPC plumbing, not relay sinks. Evidence: nmap.

---

## C. WebClient / WebDAV (coercion origin, not a relay destination)

- **SRV-LEGACY:** WebClient **enabled** — the HTTP/WebDAV coercion origin for the
  LDAP-relay leg. Evidence: `nxc smb 10.20.0.20 -M webdav` → `WebClient Service
  enabled on: 10.20.0.20`.
- **CALDER-DC01:** WebClient **not present**. Evidence: `nxc smb 10.20.0.10 -M
  webdav` → no WebClient result.

---

## D. Conceivable relay destinations proven ABSENT (by the `-p-` sweep)

- **AD CS web enrollment (HTTP 80 / HTTPS 443, `certsrv`)** — not open on either
  host. No ESC8 surface here (and certificate abuse is out of scope for 15x01).
- **MSSQL / 1433** — not open on either host; no SQL relay sink.
- **WinRM-HTTPS / 5986** — not open; only plaintext 5985 exists.
- **LDAP / LDAPS / GC on SRV-LEGACY** — absent; SRV-LEGACY is not a DC, so it
  exposes no directory relay sink.

---

## Bottom line for target selection

- **SMB relay → SRV-LEGACY only.** DC SMB signing closes the DC; every other host
  SMB endpoint is accounted for above.
- **LDAP relay → CALDER-DC01, WebDAV/HTTP origin only.** 389/3268 accept a
  non-signing origin; 636/3269 are closed by channel binding; SMB origin is
  closed by signing/EPA.
- **Coercion origin with WebClient → SRV-LEGACY.**
- WinRM, ADWS, RPC-over-HTTP, and all DC infrastructure ports are present but are
  **not** privilege-yielding relay sinks in this engagement.
- Every graded relay keeps victim and relay target on **different** hosts.

Foothold-readable flag for this task: `proof$\posture.txt` on CALDER-DC01
(`FLAG_POSTURE`).
