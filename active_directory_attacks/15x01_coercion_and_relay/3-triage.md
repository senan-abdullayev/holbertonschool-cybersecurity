# 3-triage.md — candidate verdicts with the reason attached

Every candidate from the posture map (`2-posture.md`), plus every coercion family
present, each with a **verdict** and the **specific control or decision** behind
it. The reason is the deliverable: a client learns nothing from "this is open,"
and everything from "this is open because of a choice you made." Nothing here is
asserted that was not observed; every *open* verdict is one this engagement
demonstrates (coercion in Task 1; the two relays in Tasks 4–5).

## The two reasons that matter most on this network

- **SRV-LEGACY SMB — open by oversight.** One host was never hardened. SMB signing
  is simply not required on it. This is a misconfiguration: it can be corrected on
  Monday by requiring SMB signing, and the gap closes.
- **WebDAV/HTTP-origin → LDAP on the DC — open by design scope.** The DC's LDAP
  hardening (channel binding / EPA, plus "require signing when negotiated") is
  built around TLS channels and signing-negotiated sessions. An HTTP/WebDAV origin
  negotiates **no** SMB signing and uses **no** TLS channel, so when its
  authentication is relayed into *cleartext* LDAP (389/3268) the controls have
  nothing to act on — channel binding has no channel to bind, and signing was
  never negotiated to enforce. This is not a missed setting; it is a gap in what
  the control was **designed to cover**, and it cannot be closed by flipping the
  same switch that fixes SRV-LEGACY. Closing it takes defence in depth: enforce
  LDAP signing unconditionally, remove the coercion/WebDAV origin surface (disable
  WebClient, RPC filters), and reject NTLM where Kerberos should be used.

---

## A. Relay-target candidates (from the posture map)

### SMB / 445 — CALDER-DC01 → **CLOSED**
- Control: **SMB signing required** on the DC. A relayed session cannot produce a
  valid signature, so the bind is rejected.
- Established: `nxc smb` `(signing:True)`; nmap `signing enabled and required`.

### SMB / 445 — SRV-LEGACY → **OPEN** (oversight)
- Reason: **SMB signing not required** — the one host nobody hardened. This is the
  SMB-relay target for the exec leg (Task 4).
- Established: `nxc smb` `(signing:False)`; nmap `enabled but not required`.

### LDAP 389 / GC 3268 — CALDER-DC01, **SMB origin** → **CLOSED**
- Control: **LDAP signing**, demanded because an SMB-originated relay negotiates
  signing; the DC then requires it and the bind fails.
- Established: DC hardening + confirmed by the SMB→LDAP relay being rejected
  (Task 5 negative result).

### LDAP 389 / GC 3268 — CALDER-DC01, **WebDAV/HTTP origin** → **OPEN** (design scope)
- Reason: the HTTP/WebDAV origin negotiates no signing and uses no TLS channel, so
  neither LDAP signing nor channel binding engages on a relay into cleartext LDAP.
  This is the intended LDAP-relay sink (Task 5), reached from the SRV-LEGACY
  WebDAV origin.
- Established: posture map; demonstrated by the WebDAV→LDAP relay landing in Task 5.

### LDAPS 636 / GC 3269 — CALDER-DC01 → **CLOSED**
- Control: **channel binding / EPA** on the TLS listener — a relayed bind without
  the channel-binding token is rejected.
- Established: `nxc ldap --port 636/3269` → TLS handshake reset for an unprotected
  client, consistent with EPA.

### WinRM / 5985 — CALDER-DC01 and SRV-LEGACY → **CLOSED / not viable**
- Reason: WS-Man negotiates (Kerberos/EPA); there is no NTLM-relay-to-execution
  path here, and the foothold has no WinRM access to begin with.
- Established: nmap `wsman`; `nxc winrm` → `a.foster` `[-]` on both hosts.

### ADWS 9389 / RPC-over-HTTP 593 — CALDER-DC01 → **not a relay sink**
- Reason: no ntlmrelayx path into ADWS or the RPC-over-HTTP endpoint mapper yields
  privilege in this chain.
- Established: nmap port states; no directory/exec bind is exposed.

### Conceivable sinks proven ABSENT → **not candidates**
- AD CS web enrollment (80/443), MSSQL (1433), WinRM-HTTPS (5986), and any LDAP on
  SRV-LEGACY are **not present** (full `-p-` sweep), so they are not relay
  candidates on this network.

---

## B. Coercion-family candidates (the "make a machine authenticate" surfaces)

### MS-EFSRPC / PetitPotam → **OPEN**
- Reason: the EFSRPC interface is reachable and not mitigated on this DC; the
  `EfsRpc*` calls trigger outbound authentication.
- Established: **demonstrated in Task 1** — captured `CALDER-DC01$` NetNTLMv2;
  `coerce_plus: VULNERABLE, PetitPotam`.

### MS-DFSNM / DFSCoerce → **OPEN**
- Reason: the NetrDfs interface answers and coerces authentication.
- Established: `coerce_plus: VULNERABLE, DFSCoerce`.

### MS-EVEN / EventLog (ElfrOpenBELW) → **OPEN**
- Reason: the eventlog interface is reachable and coercible.
- Established: `coerce_plus: VULNERABLE, MSEven`.

### MS-RPRN / PrinterBug → **CLOSED** (the genuinely closed one)
- Control: **Print Spooler disabled** on the DC — the MS-RPRN RPC endpoint is not
  registered, so `RpcRemoteFindFirstPrinterChangeNotificationEx` cannot be called.
- Established: `coerce_plus` PrinterBug → `ept_s_not_registered`; `-M spooler`
  returns no enabled spooler.

---

## Bottom line

- **Coercion:** EFSRPC, DFSCoerce and MS-EVEN are open; PrinterBug is closed
  (spooler off). At least one works, at least one is genuinely closed — as triaged,
  not assumed.
- **Relay:** SMB relay lands on **SRV-LEGACY only** (DC closed by signing);
  LDAP relay lands on the **DC from a WebDAV/HTTP origin only** (SMB origin closed
  by signing, TLS listeners closed by EPA).
- The two instructive gaps: SRV-LEGACY SMB is an **oversight** (fix: require
  signing); WebDAV→LDAP is a **design-scope** gap (no single switch closes it).

Foothold-readable flag for this task: `proof$\triage.txt` on CALDER-DC01
(`FLAG_TRIAGE`).
