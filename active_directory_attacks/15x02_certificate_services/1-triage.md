# 1 — Reading the Certificate Authority

## Method and scope

Enumerated as the foothold `halstead.local\j.mercer` only. For **every** published template
the same three things are mapped — (a) the **enrollment principals** (who may request it),
(b) the **template fields** (enrollee-supplies-subject, EKU, enrollment flags, approval),
and (c) **what the DC does at PKINIT** when such a cert is presented — so that closed paths
are mapped as deliberately as the open ones, not skipped. `certipy find` read the objects;
the verdicts rest on those enumerated fields and on the DC's behaviour, not on a scanner
label.

`Halstead-Root-CA` publishes **16 enabled templates** (of 38 defined). All 16 are mapped
below; the 22 unpublished ones are accounted for at the end.

Every path receives exactly one verdict:
- **OPEN** — open despite enforcement: the foothold can obtain a cert that authenticates as
  another principal.
- **WALLED** — closed by a named enforcement control (enrollment DACL, strong mapping,
  approval, EKU, or publication state).
- **DECOY** — a deceptive lookalike: carries an abuse-shaped condition but cannot
  authenticate, for a stated reason.

## CA configuration and endpoints

| Property | Value | Consequence |
|---|---|---|
| Enrollment endpoints reachable | RPC (`\pipe\cert` on `HALSTEAD-CA01`, 445) **and** Web Enrollment `/certsrv` (HTTP) | Both reachable from the foothold / the segment. |
| Web Enrollment | HTTP enabled, HTTPS disabled, **no EPA** | **OPEN (ESC8 surface).** `/certsrv` accepts NTLM over plain HTTP with no channel binding → a relayed machine authentication is honoured. |
| User-specified SAN (`EDITF_ATTRIBUTESUBJECTALTNAME2`) | Disabled | No SAN injection on non-ESS templates (no ESC6). |
| ManageCA / ManageCertificates | Admins / Domain Admins / Enterprise Admins | Foothold has no CA-officer rights (no ESC7). |
| CA Enroll right | Authenticated Users | Normal. |
| DC strong mapping | `StrongCertificateBindingEnforcement = 2`; CA emits `szOID_NTDS_CA_SECURITY_EXT` | An issued cert carries the **requester's SID**; at PKINIT the KDC binds on that SID, and only falls back to the UPN when the SID extension is absent. |

## Complete reachable surface — all 16 published templates

| # | Template | Enrollment principals | ESS | Logon EKU? | Approval / flags | DC at PKINIT | Verdict |
|---|---|---|---|---|---|---|---|
| 1 | HalsteadWorkstationEnroll | Domain Users | **Yes** | Yes (Client Auth) | none | SID ext = j.mercer ≠ `SAN UPN=administrator` → **`KDC_ERR_CLIENT_NAME_MISMATCH`** | **WALLED** (strong mapping) |
| 2 | HalsteadVPNAccess | Domain Users | No | Yes (SC Logon + Client Auth) | **NoSecurityExtension** | no SID ext → KDC matches **UPN** → authenticates as that UPN | **OPEN** (no-SID gap) |
| 3 | HalsteadServiceCert | Domain Users | No | Yes (Client Auth) | j.mercer has **Full Control** on the object | foothold can rewrite the template, then enrol a cert that logs on as the victim | **OPEN** (writable template) |
| 4 | HalsteadMgrApproval | Domain Users | Yes | Yes (Client Auth) | **PendAllRequests** (approval) | never issued → PKINIT never reached | **WALLED** (approval) |
| 5 | HalsteadCodeSign | Domain Users | Yes | **No** (Code Signing) | none | cert carries no logon EKU → not accepted for PKINIT | **DECOY** |
| 6 | User | Domain Users, Domain/Enterprise Admins | No | Yes (Client Auth) | none | ESS=False → SID ext binds cert to **j.mercer** → logs on as self | **WALLED** (strong mapping) |
| 7 | EFS | Domain Users, Domain/Enterprise Admins | No | **No** (Encrypting File System) | none | no logon EKU → not accepted for PKINIT | **WALLED** (EKU) |
| 8 | Machine | Domain Computers, Domain/Enterprise Admins | No | Yes | none | foothold not an enrollment principal → cannot enrol | **WALLED** (enrollment DACL) |
| 9 | DomainController | DCs, Domain/Enterprise Admins | No | Yes | none | foothold cannot enrol (a *coerced DC account* enrols it via the ESC8 relay — the CA-endpoint OPEN above, not this path) | **WALLED** (enrollment DACL) |
| 10 | DomainControllerAuthentication | DCs, Domain/Enterprise Admins | No | Yes | none | foothold cannot enrol | **WALLED** (enrollment DACL) |
| 11 | KerberosAuthentication | DCs, Domain/Enterprise Admins | No | Yes | none | foothold cannot enrol | **WALLED** (enrollment DACL) |
| 12 | DirectoryEmailReplication | DCs, Domain/Enterprise Admins | No | **No** (DS Email Replication) | none | foothold cannot enrol | **WALLED** (enrollment DACL) |
| 13 | SubCA | Domain/Enterprise Admins | Yes | No (no EKU) | none | foothold cannot enrol | **WALLED** (enrollment DACL) |
| 14 | WebServer | Domain/Enterprise Admins | Yes | **No** (Server Auth) | none | foothold cannot enrol | **WALLED** (enrollment DACL) |
| 15 | Administrator | Domain/Enterprise Admins | No | Yes (Client Auth) | none | foothold cannot enrol | **WALLED** (enrollment DACL) |
| 16 | EFSRecovery | Domain/Enterprise Admins | No | **No** (File Recovery) | none | foothold cannot enrol | **WALLED** (enrollment DACL) |

## The decided paths, in detail

### HalsteadWorkstationEnroll — WALLED (strong mapping)
The enrollee controls the subject and the EKU can log on — the classic abuse shape, so it is
**tested, not assumed**:
```
certipy req  ... -target HALSTEAD-CA01 -template HalsteadWorkstationEnroll \
                 -upn administrator@halstead.local   -> cert issued (SID extension = j.mercer's SID)
certipy auth -pfx administrator.pfx -dc-ip 10.20.0.10 -> KDC_ERR_CLIENT_NAME_MISMATCH
```
The CA stamps the requester's SID (`1.3.6.1.4.1.311.25.2`); the KDC binds on that SID
(j.mercer), not on the supplied `SAN UPN=administrator`, and rejects the mismatch. Supplying
a privileged name does not help — calling this exploitable would be a triage fault.

### HalsteadVPNAccess — OPEN (no-SID gap)
`NoSecurityExtension` makes issued certs **omit** the SID extension — the exact field that
walls WorkstationEnroll — so the KDC falls back to matching on the UPN. The foothold holds
**GenericWrite over `svc-scan`** (BloodHound edge `J.MERCER → svc-scan`): set `svc-scan`'s
UPN to the victim, enrol here, and PKINIT returns the victim (demonstrated in Task 3). This
is the one published path enforcement does not reach.

### HalsteadServiceCert — OPEN (writable template)
The open vector is the template's **object DACL**, not its current flags: `j.mercer` holds
**Full Control / Write-Owner / Write-DACL**. The foothold rewrites the template into an
exploitable state (enrollee-supplies-subject, or NoSecurityExtension), enrols a cert that
logs on as the victim, then restores the template (demonstrated in Task 4).

### HalsteadMgrApproval — WALLED (approval)
Same enrollee-supplies-subject shape as WorkstationEnroll, which is why it must be
distinguished. `PendAllRequests` (`Requires Manager Approval = True`) holds every request
for a CA officer, so the foothold never obtains a cert.

### HalsteadCodeSign — DECOY
Enrollee-controls-subject shape again, but the EKU is **Code Signing only** (no Client Auth,
no Smart Card Logon). It resembles the abusable case yet the issued cert carries no logon
EKU and can never be used for Kerberos/PKINIT whatever subject is supplied.

## Unpublished templates (not reachable) — WALLED (publication)

Enumerated but `Enabled = False` on `Halstead-Root-CA`: the CA will not process a request
for any of them, so no enrollment path exists regardless of their flags. The 22: `CA,
CAExchange, CEPEncryption, CTLSigning, ClientAuth, CodeSigning, CrossCA, EnrollmentAgent,
EnrollmentAgentOffline, ExchangeUser, ExchangeUserSignature, IPSECIntermediateOffline,
IPSECIntermediateOnline, KeyRecoveryAgent, MachineEnrollmentAgent, OCSPResponseSigning,
OfflineRouter, RASAndIASServer, SmartcardLogon, SmartcardUser, UserSignature, Workstation`.

## Key observation

Across the whole published surface only two template-paths are **OPEN** — HalsteadVPNAccess
(no SID extension) and HalsteadServiceCert (writable object) — plus the CA's **OPEN** web
-enrollment endpoint (ESC8). Everything else is **WALLED** by a specific control
(enrollment DACL for the stock templates, strong mapping for WorkstationEnroll and User,
approval for MgrApproval), with one **DECOY** (CodeSign). Three enabled templates share the
enrollee-supplies-subject shape and are each decided by a *different* control — strong
mapping, approval, EKU — which is why the triage turns on what the DC actually consults, not
on how a template looks.
