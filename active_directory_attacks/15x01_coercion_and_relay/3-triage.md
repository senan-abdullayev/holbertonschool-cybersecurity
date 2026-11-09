# 3-triage.md — candidate verdicts with the reason attached

Every candidate from the posture map (`2-posture.md`) is matched to a **host +
service** and given exactly one verdict from a fixed vocabulary:

- **OPEN** — usable as a relay/coercion sink in this engagement.
- **CLOSED** — not usable, with the specific control or fact that closes it.
- **UNRESOLVED** — evidence cannot support either conclusion (none on this map;
  every candidate here is resolved).

No candidate is dropped for being "uninteresting": services that cannot receive a
privilege-yielding relay are classified **CLOSED** with the reason, not removed.
The reason is the deliverable — a client acts on *why*, not on the verdict.

## Verdict table (every host/service candidate)

| Host | Service / Port | Verdict | Control / reason |
|------|----------------|---------|------------------|
| CALDER-DC01 | SMB / 445 | **CLOSED** | SMB signing **required** — a relayed session cannot sign |
| SRV-LEGACY | SMB / 445 | **OPEN** | SMB signing **not required** (unhardened host) |
| CALDER-DC01 | LDAP / 389 | **OPEN** | relayable via a WebDAV/HTTP origin (SMB-origin path closed by signing) |
| CALDER-DC01 | GC-LDAP / 3268 | **OPEN** | same as 389 — distinct listener, same result |
| CALDER-DC01 | LDAPS / 636 | **CLOSED** | channel binding / EPA on the TLS listener |
| CALDER-DC01 | GC-LDAPS / 3269 | **CLOSED** | channel binding / EPA (TLS listener) |
| CALDER-DC01 | WinRM / 5985 | **CLOSED** | WS-Man negotiates (Kerberos/EPA); no NTLM-relay-to-exec path |
| SRV-LEGACY | WinRM / 5985 | **CLOSED** | same — no NTLM-relay-to-exec path |
| CALDER-DC01 | RPC-over-HTTP / 593 | **CLOSED** | endpoint mapper only; no relay bind an attacker gains from |
| CALDER-DC01 | ADWS / 9389 | **CLOSED** | no ntlmrelayx path into ADWS yields privilege |
| CALDER-DC01 | RPC epmapper / 135, NetBIOS / 139, kpasswd / 464, ephemeral RPC / 49664-49711 | **CLOSED** | not NTLM-authentication endpoints |
| CALDER-DC01 | DNS / 53, Kerberos / 88 | **CLOSED** | not NTLM endpoints |
| SRV-LEGACY | RPC epmapper / 135, NetBIOS / 139 | **CLOSED** | not NTLM-authentication endpoints |
| CALDER-DC01 | AD CS web 80/443, MSSQL 1433, WinRM-HTTPS 5986 | **CLOSED** | no listener — absent on the `-p-` sweep |
| SRV-LEGACY | LDAP/LDAPS/GC, AD CS web, MSSQL | **CLOSED** | no listener — SRV-LEGACY is not a DC |

Every verdict's evidence:
- SMB: `nxc smb` (`signing:True` DC / `signing:False` SRV) + nmap `smb2-security-mode`.
- LDAP 389 / GC 3268 OPEN: posture map; demonstrated by the WebDAV→LDAP relay
  landing in Task 5.
- LDAPS 636 / GC 3269 CLOSED: `nxc ldap --port 636/3269` → TLS handshake reset for
  an unprotected client, consistent with EPA.
- WinRM CLOSED: nmap `wsman`; `nxc winrm` → `a.foster` `[-]` on both hosts.
- 593 / 9389 / infrastructure ports CLOSED: nmap service identification.
- Absent sinks CLOSED: full `nmap -Pn -p-` of both hosts (no such listener).

## The two reasons that matter most on this network

- **SRV-LEGACY SMB — open by oversight.** One host was never hardened; SMB signing
  is simply not required on it. A misconfiguration: corrected on Monday by
  requiring SMB signing, and the gap closes.
- **WebDAV/HTTP-origin → LDAP on the DC — open by design scope.** The DC's LDAP
  hardening (channel binding / EPA, plus "require signing when negotiated") is
  built around TLS channels and signing-negotiated sessions. A WebDAV/HTTP origin
  negotiates **no** SMB signing and uses **no** TLS channel, so relayed into
  *cleartext* LDAP (389/3268) the controls have nothing to act on — channel
  binding has no channel to bind, signing was never negotiated to enforce. This is
  why LDAP/389 and GC/3268 are **OPEN** despite the DC being hardened: not a missed
  setting, but a gap in what the control was **designed to cover**. It cannot be
  closed by the switch that fixes SRV-LEGACY; it takes defence in depth — enforce
  LDAP signing unconditionally, remove the coercion/WebDAV origin surface (disable
  WebClient, RPC filters), reject NTLM where Kerberos should be used.

## Coercion-family candidates

| Family | Verdict | Control / reason | Evidence |
|--------|---------|------------------|----------|
| MS-EFSRPC / PetitPotam | **OPEN** | EFSRPC reachable, unmitigated | Task-1 capture of `CALDER-DC01$`; `coerce_plus: VULNERABLE, PetitPotam` |
| MS-DFSNM / DFSCoerce | **OPEN** | NetrDfs interface coercible | `coerce_plus: VULNERABLE, DFSCoerce` |
| MS-EVEN / EventLog | **OPEN** | eventlog interface coercible | `coerce_plus: VULNERABLE, MSEven` |
| MS-RPRN / PrinterBug | **CLOSED** | **Print Spooler disabled** — RPC endpoint not registered | `coerce_plus` PrinterBug → `ept_s_not_registered`; `-M spooler` shows none |

## Bottom line

- **Relay:** SMB relay lands on **SRV-LEGACY only** (DC closed by signing); LDAP
  relay lands on the **DC from a WebDAV/HTTP origin only** (TLS listeners closed by
  EPA, SMB origin closed by signing). All other services are CLOSED with reason.
- **Coercion:** EFSRPC, DFSCoerce, MS-EVEN open; PrinterBug closed (spooler off).
- The two instructive gaps: SRV-LEGACY SMB is an **oversight** (require signing);
  WebDAV→LDAP is a **design-scope** gap (no single switch closes it).

Foothold-readable flag for this task: `proof$\triage.txt` on CALDER-DC01
(`FLAG_TRIAGE`).
