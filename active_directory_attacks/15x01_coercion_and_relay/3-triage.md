# 3-triage.md — candidate verdicts with the reason attached

Every candidate is matched **one-to-one** to a single host + service/port and
given exactly one verdict. No line groups two services; no candidate is dropped.

Verdict vocabulary:
- **OPEN** — usable as a relay/coercion sink in this engagement.
- **CLOSED** — not usable, with the specific control or fact that closes it.
- **UNRESOLVED** — evidence cannot support either conclusion (none here; every
  candidate on this map is resolved).

Candidates are presented in four separate scopes so relay, infrastructure,
absent, and coercion candidates are never mixed on one line.

---

## Scope 1 — NTLM relay-sink candidates (one row per host/port)

| Host | Service / Port | Verdict | Control / reason | Evidence |
|------|----------------|---------|------------------|----------|
| CALDER-DC01 | SMB / 445 | **CLOSED** | SMB signing required; a relayed session cannot sign | `nxc smb` `signing:True`; nmap `enabled and required` |
| CALDER-DC01 | LDAP / 389 | **OPEN** | relayable from a WebDAV/HTTP origin; SMB-origin path closed by signing | posture map; demonstrated by WebDAV→LDAP relay (Task 5) |
| CALDER-DC01 | LDAPS / 636 | **CLOSED** | channel binding / EPA on the TLS listener | `nxc ldap --port 636` → TLS reset for unprotected client |
| CALDER-DC01 | GC-LDAP / 3268 | **OPEN** | distinct listener, same result as 389 (WebDAV-origin relayable) | posture map; WebDAV→LDAP relay (Task 5) |
| CALDER-DC01 | GC-LDAPS / 3269 | **CLOSED** | channel binding / EPA on the TLS listener | `nxc ldap --port 3269` → TLS listener, EPA basis |
| CALDER-DC01 | RPC-over-HTTP / 593 | **CLOSED** | endpoint mapper only; no relay bind an attacker gains from | nmap `http-rpc-epmap` |
| CALDER-DC01 | WinRM / 5985 | **CLOSED** | WS-Man negotiates (Kerberos/EPA); no NTLM-relay-to-exec path | nmap `wsman`; `nxc winrm` → `a.foster` `[-]` |
| CALDER-DC01 | ADWS / 9389 | **CLOSED** | no ntlmrelayx path into ADWS yields privilege | nmap `adws` |
| SRV-LEGACY | SMB / 445 | **OPEN** | SMB signing not required (unhardened host) — SMB-relay exec target | `nxc smb` `signing:False`; nmap `enabled but not required` |
| SRV-LEGACY | WinRM / 5985 | **CLOSED** | WS-Man; no NTLM-relay-to-exec path | nmap `wsman`; `nxc winrm` → `a.foster` `[-]` |

## Scope 2 — Open ports that are not NTLM-authentication endpoints (one row each)

| Host | Service / Port | Verdict | Control / reason |
|------|----------------|---------|------------------|
| CALDER-DC01 | DNS / 53 | **CLOSED** | not an NTLM endpoint |
| CALDER-DC01 | Kerberos / 88 | **CLOSED** | not an NTLM endpoint |
| CALDER-DC01 | RPC epmapper / 135 | **CLOSED** | not an NTLM-authentication endpoint |
| CALDER-DC01 | NetBIOS-SSN / 139 | **CLOSED** | legacy SMB transport; DC signing still applies, no relay gain |
| CALDER-DC01 | kpasswd / 464 | **CLOSED** | not an NTLM endpoint |
| CALDER-DC01 | Dynamic RPC / 49664 | **CLOSED** | not an NTLM-authentication endpoint |
| CALDER-DC01 | Dynamic RPC / 49667 | **CLOSED** | not an NTLM-authentication endpoint |
| CALDER-DC01 | Dynamic RPC / 49669 | **CLOSED** | not an NTLM-authentication endpoint |
| CALDER-DC01 | Dynamic RPC / 49676 | **CLOSED** | not an NTLM-authentication endpoint |
| CALDER-DC01 | Dynamic RPC / 49679 | **CLOSED** | not an NTLM-authentication endpoint |
| CALDER-DC01 | Dynamic RPC / 49683 | **CLOSED** | not an NTLM-authentication endpoint |
| CALDER-DC01 | Dynamic RPC / 49690 | **CLOSED** | not an NTLM-authentication endpoint |
| CALDER-DC01 | Dynamic RPC / 49711 | **CLOSED** | not an NTLM-authentication endpoint |
| SRV-LEGACY | RPC epmapper / 135 | **CLOSED** | not an NTLM-authentication endpoint |
| SRV-LEGACY | NetBIOS-SSN / 139 | **CLOSED** | legacy SMB transport; same host as 445, no separate relay gain |

Evidence for Scope 2: `nmap -Pn -p-` service identification on both hosts.

## Scope 3 — Conceivable relay sinks proven absent (one row each)

| Host | Service / Port | Verdict | Control / reason |
|------|----------------|---------|------------------|
| CALDER-DC01 | AD CS web enrollment / 80 | **CLOSED** | no listener (absent on `-p-` sweep) |
| CALDER-DC01 | AD CS web enrollment / 443 | **CLOSED** | no listener (absent on `-p-` sweep) |
| CALDER-DC01 | MSSQL / 1433 | **CLOSED** | no listener (absent) |
| CALDER-DC01 | WinRM-HTTPS / 5986 | **CLOSED** | no listener (absent) |
| SRV-LEGACY | LDAP / 389 | **CLOSED** | no listener — SRV-LEGACY is not a DC |
| SRV-LEGACY | LDAPS / 636 | **CLOSED** | no listener — not a DC |
| SRV-LEGACY | GC-LDAP / 3268 | **CLOSED** | no listener — not a DC |
| SRV-LEGACY | GC-LDAPS / 3269 | **CLOSED** | no listener — not a DC |
| SRV-LEGACY | AD CS web / 80,443 | **CLOSED** | no listener (absent) |
| SRV-LEGACY | MSSQL / 1433 | **CLOSED** | no listener (absent) |

Evidence for Scope 3: full `nmap -Pn -p-` of both hosts (ports not present).

## Scope 4 — Coercion-family candidates (one row each)

| Family / Transport | Verdict | Control / reason | Evidence |
|--------------------|---------|------------------|----------|
| MS-EFSRPC / PetitPotam | **OPEN** | EFSRPC reachable, unmitigated | Task-1 capture of `CALDER-DC01$`; `coerce_plus: VULNERABLE, PetitPotam` |
| MS-DFSNM / DFSCoerce | **OPEN** | NetrDfs interface coercible | `coerce_plus: VULNERABLE, DFSCoerce` |
| MS-EVEN / EventLog | **OPEN** | eventlog interface coercible | `coerce_plus: VULNERABLE, MSEven` |
| MS-RPRN / PrinterBug | **CLOSED** | Print Spooler disabled; RPC endpoint not registered | `coerce_plus` → `ept_s_not_registered`; `-M spooler` none |

---

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

## Bottom line

- **Relay:** SMB relay lands on **SRV-LEGACY / 445 only**; LDAP relay lands on the
  **DC LDAP 389 / GC 3268 from a WebDAV/HTTP origin only**. Every other service is
  CLOSED with its reason above.
- **Coercion:** EFSRPC, DFSCoerce, MS-EVEN open; PrinterBug closed (spooler off).
- The two instructive gaps: SRV-LEGACY SMB is an **oversight** (require signing);
  WebDAV→LDAP is a **design-scope** gap (no single switch closes it).

Foothold-readable flag for this task: `proof$\triage.txt` on CALDER-DC01
(`FLAG_TRIAGE`).
