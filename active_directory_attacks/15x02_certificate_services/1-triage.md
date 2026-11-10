# 1 — Reading the Certificate Authority

## Method

Enumerated as the foothold `halstead.local\j.mercer` only. Source: `certipy-ad find`
(38 templates total, **16 enabled/published** to `Halstead-Root-CA`), the per-template
fields (enrollment rights, name/enrollment flags, EKU, approval), the CA configuration,
and — where a verdict claims **OPEN** or **WALLED** — an actual request + PKINIT, because a
verdict is a claim to be demonstrated, not asserted.

Exactly three verdicts, and every path below carries exactly one of them:

- **OPEN** — open despite enforcement (exploitable from the foothold).
- **WALLED** — closed by an enforcement control (strong mapping, approval, enrollment ACL,
  EKU scoping, or publication state).
- **DECOY** — a deceptive lookalike: resembles a known abuse case but is neither open nor a
  wall around a real one (a day-waster).

## Authority (CA) configuration

| Property | Value | Verdict / consequence |
|---|---|---|
| Web Enrollment | HTTP enabled, HTTPS disabled, no EPA | **ESC8 — OPEN.** `/certsrv` is a relay target (plain HTTP, no channel binding). |
| User Specified SAN (`EDITF_ATTRIBUTESUBJECTALTNAME2`) | Disabled | No ESC6 — the CA will not honour an attacker SAN on a non-ESS template. |
| ManageCA / ManageCertificates | Admins / Domain Admins / Enterprise Admins only | No ESC7 — foothold has no CA-officer rights. |
| Enroll (CA) | Authenticated Users | Normal. |
| KDC strong mapping | `StrongCertificateBindingEnforcement = 2`; CA stamps `szOID_NTDS_CA_SECURITY_EXT` | Active — a cert carries the requester's SID; the KDC binds on it, not on the SAN. |

## Custom templates (the deliberate zoo)

### 1. HalsteadWorkstationEnroll — **WALLED**
- certipy tag: ESC1. Fields: `Enrollee Supplies Subject = True`, Client Authentication EKU,
  no approval, enrollment = Domain Users.
- Enforcement that closes it: **strong mapping.** Decided by measurement:
  ```
  certipy req  ... -target HALSTEAD-CA01.halstead.local -template HalsteadWorkstationEnroll \
                   -upn administrator@halstead.local      -> cert issued (SID ext = j.mercer's SID)
  certipy auth -pfx administrator.pfx -dc-ip 10.20.0.10   -> KDC_ERR_CLIENT_NAME_MISMATCH
  ```
  The CA stamps the requester's SID (1.3.6.1.4.1.311.25.2); at PKINIT the KDC binds on that
  SID (j.mercer), not on the supplied `SAN UPN=administrator`, and rejects the mismatch. The
  famous attack fails; the error names the field consulted and confirms it was present.
  ESS does not help here — claiming it exploitable is a triage fault.

### 2. HalsteadVPNAccess — **OPEN**
- certipy tag: ESC9. Fields: `Enrollment Flag = PublishToDs, NoSecurityExtension`,
  `Name Flag = SubjectAltRequireUpn`, Smart Card Logon + Client Authentication EKU,
  enrollment = Domain Users.
- Open despite enforcement: `NoSecurityExtension` makes issued certs **omit** the SID
  extension — the field that walls #1 is absent, so the KDC falls back to UPN mapping.
  Prerequisite confirmed: foothold holds **GenericWrite over `svc-scan`** (BloodHound
  `J.MERCER → svc-scan`), a settable UPN on a controllable account. Set `svc-scan`'s UPN to
  the victim, enrol here, PKINIT as the victim.

### 3. HalsteadServiceCert — **OPEN**
- certipy tag: ESC4. Fields: `Enrollee Supplies Subject = False`, Client Authentication EKU,
  no approval.
- Open despite enforcement: not abusable as configured, but `j.mercer` holds **Full Control
  / Write-Owner / Write-DACL** over the template object — rewrite it into an exploitable
  condition, enrol, then restore (Task 4).

### 4. HalsteadMgrApproval — **WALLED**
- Fields: `Enrollee Supplies Subject = True` + Client Authentication EKU — the **identical
  ESC1 shape as #1**. Enforcement that closes it: **manager approval** (`Enrollment Flag =
  PendAllRequests`, `Requires Manager Approval = True`). Every request pends for a CA
  officer and never auto-issues, so the foothold obtains no cert. Named precisely because it
  looks like ESC1 and the next tester will wait on it.

### 5. HalsteadCodeSign — **DECOY**
- Fields: `Enrollee Supplies Subject = True` (the ESC1 shape again) but EKU = **Code Signing
  only** (`Client Authentication = False`, no Smart Card Logon). A deceptive lookalike: it
  presents the enrollee-supplies-subject condition but the issued cert can never be used for
  Kerberos/PKINIT, whatever subject you supply. Neither open nor a wall around a real case.

## Default enabled templates — one verdict per path

| # | Template | Verdict | Enforcement control / reason (evidence) |
|---|---|---|---|
| 6 | User | **WALLED** | Enrollable by Domain Users and Client-Auth capable, but `ESS=False` → the SID extension binds the issued cert to **j.mercer**; it authenticates as yourself. Strong mapping closes the escalation. |
| 7 | EFS | **WALLED** | Enrollable by Domain Users, but EKU = Encrypting File System only — no Client Auth / Smart Card Logon, so the cert cannot authenticate to AD. EKU scoping closes it. |
| 8 | Machine | **WALLED** | Enrollment restricted to Domain Computers / Admins; the foothold (a user) has no enrollment right. `ESS=False`. |
| 9 | DomainController | **WALLED** | Enrollment restricted to DCs / Admins; no foothold right. (The DC machine account enrols this via the ESC8 relay — that OPEN finding sits at the CA web-enrollment layer, not this foothold-enrollment path.) |
| 10 | DomainControllerAuthentication | **WALLED** | As #9 — DCs / Admins only; no foothold enrollment right. |
| 11 | KerberosAuthentication | **WALLED** | Enrollment DCs / Admins only; `ESS=False`, subject is the authenticating machine. |
| 12 | DirectoryEmailReplication | **WALLED** | Enrollment DCs / Admins only; EKU (DS Email Replication) is not a logon EKU. |
| 13 | SubCA | **WALLED** | `ESS=True` (ESC1 shape) **but** enrollment restricted to Domain / Enterprise Admins — foothold cannot enrol. |
| 14 | WebServer | **WALLED** | `ESS=True` but Admins-only enrollment, and Server Authentication EKU cannot client-auth. |
| 15 | Administrator | **WALLED** | Enrollment Admins-only; `ESS=False`. Foothold cannot enrol. |
| 16 | EFSRecovery | **WALLED** | Enrollment Admins-only; File Recovery EKU is not an auth EKU. |

## Disabled templates — **WALLED** (one verdict, one shared dispositive fact)

Each of the following is **WALLED**: it is `Enabled = False` (not published to
`Halstead-Root-CA`), so the CA will not process a request for it and no enrollment path
exists, regardless of its flags. The 22: `CA, CAExchange, CEPEncryption, CTLSigning,
ClientAuth, CodeSigning, CrossCA, EnrollmentAgent, EnrollmentAgentOffline, ExchangeUser,
ExchangeUserSignature, IPSECIntermediateOffline, IPSECIntermediateOnline, KeyRecoveryAgent,
MachineEnrollmentAgent, OCSPResponseSigning, OfflineRouter, RASAndIASServer, SmartcardLogon,
SmartcardUser, UserSignature, Workstation`.

## Summary

| Path | certipy shape | Verdict |
|---|---|---|
| HalsteadVPNAccess | ESC9 | **OPEN** |
| HalsteadServiceCert | ESC4 | **OPEN** |
| CA web enrollment | ESC8 | **OPEN** |
| HalsteadWorkstationEnroll | ESC1 | **WALLED** (strong mapping) |
| HalsteadMgrApproval | ESC1 | **WALLED** (approval) |
| User, EFS, Machine, DomainController, DomainControllerAuthentication, KerberosAuthentication, DirectoryEmailReplication, SubCA, WebServer, Administrator, EFSRecovery | default | **WALLED** (per-row reason above) |
| 22 disabled templates | default | **WALLED** (not published) |
| HalsteadCodeSign | ESC1 | **DECOY** |

## Key observation

Three enabled templates share the ESC1 enrollee-supplies-subject shape, and each is closed
or opened by a different thing: **HalsteadWorkstationEnroll** is WALLED by strong mapping,
**HalsteadMgrApproval** is WALLED by approval, **HalsteadCodeSign** is a DECOY by EKU. The
one path where the wall does not reach is **HalsteadVPNAccess** — `NoSecurityExtension`
removes the SID field the wall depends on — which, with the writable `svc-scan` UPN, is
OPEN and is where the rest of the chain begins. The discipline is separating these by what
the DC actually consults, not by how the template looks.
