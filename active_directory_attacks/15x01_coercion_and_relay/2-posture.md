# 2-posture.md — Calder defensive posture map

Method: every value below was **observed**, not taken from a Microsoft default.
Tools used from the foothold (`calder.local\a.foster`): `nmap` (SMB security
mode), NetExec `nxc smb/ldap` (signing + channel-binding banner, WebDAV module),
and the coercion result from Task 1. Each row records how it was established.
Relay verdicts that depend on origin are confirmed again by the relay outcome in
the later tasks; where that is the case it is stated.

## Hosts

- **CALDER-DC01** — `10.20.0.10`, Windows Server 2022 Build 20348, domain
  controller, hardened.
- **SRV-LEGACY** — `10.20.0.20`, Windows Server 2022 Build 20348, domain member,
  unhardened.

## Relay-relevant services

### SMB / 445 — CALDER-DC01
- Protocol: SMB 3.1.1.
- Signing: **required**.
- Channel binding / EPA: n/a (SMB).
- Relay verdict: **CLOSED** — a relayed session cannot sign, so the DC rejects it.
- Established by: `nxc smb 10.20.0.10` → `(signing:True)`; nmap
  `smb2-security-mode: Message signing enabled and required`.

### SMB / 445 — SRV-LEGACY
- Protocol: SMB 3.1.1.
- Signing: **not required**.
- Channel binding / EPA: n/a (SMB).
- Relay verdict: **OPEN** — this is the SMB-relay target for the exec leg.
- Established by: `nxc smb 10.20.0.20` → `(signing:False)`; nmap
  `smb2-security-mode: Message signing enabled but not required`.

### LDAP / 389 + LDAPS / 636 — CALDER-DC01
- Protocol: LDAP (389) and LDAPS (636).
- Signing: enforced.
- Channel binding / EPA: **on** (Extended Protection for Authentication).
- Relay verdict: **SMB-origin → LDAP CLOSED, WebDAV/HTTP-origin → LDAP OPEN.**
  An SMB-originated relay carries the signing-negotiated flags, so the DC
  demands signing/CB and rejects the bind. A WebDAV/HTTP-originated relay does
  not negotiate SMB signing, and channel binding is a TLS-scoped control, so the
  relay into LDAP succeeds — this is the intended LDAP-relay leg.
- Established by: `nxc ldap 10.20.0.10` banner (signing/channel-binding fields);
  LDAPS 636 handshake reset for an unprotected client (`ECONNRESET`), consistent
  with EPA; **confirmed** by the relay behaviour in the LDAPRELAY task.

### WebClient / WebDAV — SRV-LEGACY (origin, not a relay target)
- Protocol: WebDAV over HTTP (MS-WEBDAV via WebClient service).
- State: **enabled**.
- Relay relevance: the HTTP/WebDAV **coercion origin** that produces the
  HTTP-authentication used in the LDAP-relay leg.
- Established by: `nxc smb 10.20.0.20 -M webdav` → `WebClient Service enabled`.

### WebClient / WebDAV — CALDER-DC01
- State: **not present** (service not advertised).
- Established by: `nxc smb 10.20.0.10 -M webdav` → no WebClient result.

## Services listed but NOT viable relay targets (the closed half of the map)

- **HTTP / 5985 (WinRM)** — DC and SRV-LEGACY. Open ports, but no cross-protocol
  NTLM-relay path here yields privilege in this engagement; not a relay target.
  Established by: nmap port state (`5985/tcp open http Microsoft-HTTPAPI`).
- **DNS / 53, Kerberos / 88, kpasswd / 464, RPC / 135 + 593 (ncacn_http),
  LDAP-GC / 3268-3269** — CALDER-DC01. Standard DC services; none is an
  NTLM-relay sink that advances this chain. Listed for completeness.
  Established by: nmap `-A` service scan of `10.20.0.10`.

## Bottom line for target selection

- SMB relay → **SRV-LEGACY only** (DC signing closes the DC).
- LDAP relay → **DC, WebDAV/HTTP origin only** (SMB origin is closed by
  signing + EPA).
- Coercion origin with WebClient → **SRV-LEGACY**.
- Every graded relay keeps victim and relay target on **different** hosts.

Foothold-readable flag for this task: `proof$\posture.txt` on CALDER-DC01
(`FLAG_POSTURE`).
