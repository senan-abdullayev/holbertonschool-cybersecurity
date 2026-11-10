# 1 — Reading the Certificate Authority

## Method

Enumerated as the foothold `halstead.local\j.mercer` only (`certipy find` was used to read
the objects, but each verdict below rests on the template's own enumerated fields —
enrollment rights, name/enrollment flags, EKU, approval — and on what the DC does when a
cert is presented, not on any scanner label). 38 templates exist; **16 are enabled**
(published to `Halstead-Root-CA`) and are the live enrollment paths. The keystone wall is
proven by an actual request + PKINIT; the two open template-paths are proven exploitable in
Tasks 3–4; the rest are closed on fields observed during enumeration.

Exactly three verdicts, and every path carries exactly one:

- **OPEN** — open despite enforcement (the foothold can obtain a cert that authenticates as
  someone else).
- **WALLED** — closed by an enforcement control (strong mapping, approval, the enrollment
  DACL, the EKU, or publication state), with the specific control named per path.
- **DECOY** — a deceptive lookalike: carries a condition that resembles a known abuse case
  but cannot be used to authenticate, for a stated reason.

## Authority (CA) configuration

| Property | Value | Verdict / consequence |
|---|---|---|
| Web Enrollment | HTTP enabled, HTTPS disabled, no EPA | **OPEN** — `/certsrv` accepts NTLM over plain HTTP with no channel binding, so a relayed machine authentication is honoured. |
| User-specified SAN (`EDITF_ATTRIBUTESUBJECTALTNAME2`) | Disabled | Not abusable — the CA will not honour an attacker SAN on a non-ESS template. |
| ManageCA / ManageCertificates | Admins / Domain Admins / Enterprise Admins only | Not abusable — foothold has no CA-officer rights. |
| Enroll (CA) | Authenticated Users | Normal. |
| KDC strong mapping | `StrongCertificateBindingEnforcement = 2`; CA emits `szOID_NTDS_CA_SECURITY_EXT` | Active — an issued cert carries the requester's SID; the KDC binds on that SID, not on the SAN. |

## Custom templates

### 1. HalsteadWorkstationEnroll — **WALLED**
Observed: `Enrollee Supplies Subject = True`, Client Authentication EKU, no approval,
enrollment = Domain Users — i.e. the enrollee controls the subject and the cert can log on.
That is the classic enrollee-supplies-subject condition, so it must be *tested*, not
assumed. Measured:
```
certipy req  ... -target HALSTEAD-CA01 -template HalsteadWorkstationEnroll \
                 -upn administrator@halstead.local   -> cert issued (SID extension = j.mercer's SID)
certipy auth -pfx administrator.pfx -dc-ip 10.20.0.10 -> KDC_ERR_CLIENT_NAME_MISMATCH
```
**Control that closes it: strong mapping.** The CA stamps the requester's SID
(`1.3.6.1.4.1.311.25.2`); at PKINIT the KDC binds on that SID (j.mercer) rather than the
supplied `SAN UPN=administrator`, and rejects the mismatch. Supplying a privileged name does
not help — calling this exploitable would be a triage fault.

### 2. HalsteadVPNAccess — **OPEN**
Observed: `Enrollment Flag = PublishToDs, NoSecurityExtension`, `Name Flag =
SubjectAltRequireUpn`, Smart Card Logon + Client Authentication EKU, enrollment = Domain
Users. **Why enforcement does not reach it:** the `NoSecurityExtension` flag means issued
certs omit the SID extension — the exact field that walls #1 — so the KDC falls back to
matching on the UPN. Prerequisite verified during enumeration: the foothold holds
**GenericWrite over `svc-scan`** (BloodHound edge `J.MERCER → svc-scan`), i.e. a UPN it can
set on a controllable account. Set `svc-scan`'s UPN to the victim, enrol here, and PKINIT
returns the victim (demonstrated in Task 3).

### 3. HalsteadServiceCert — **OPEN**
Observed: `Enrollee Supplies Subject = False`, Client Authentication EKU, no approval — not
abusable as it stands. **Why enforcement does not reach it:** the template's own object DACL
grants `j.mercer` **Full Control / Write-Owner / Write-DACL**, so the foothold can rewrite
the template into an exploitable state, enrol, and restore it (demonstrated in Task 4). The
weakness is in the ACL enumerated on the object, not in its current flags.

### 4. HalsteadMgrApproval — **WALLED**
Observed: `Enrollee Supplies Subject = True` + Client Authentication EKU — the **same
enrollee-supplies-subject condition as #1**, which is why it has to be distinguished. **Control
that closes it: manager approval.** `Enrollment Flag = PendAllRequests`
(`Requires Manager Approval = True`): every request pends for a CA officer and never
auto-issues, so the foothold obtains no usable cert.

### 5. HalsteadCodeSign — **DECOY**
Observed: `Enrollee Supplies Subject = True` — again the enrollee-controls-subject shape —
but the EKU is **Code Signing only** (`Client Authentication = False`, no Smart Card Logon).
It resembles the abusable case yet the issued cert carries no logon EKU, so it can never be
used for Kerberos/PKINIT whatever subject is supplied. Viable for nothing here.

## Default enabled templates — one verdict per path, from observed fields

| # | Template | Verdict | Observed field → control that decides it |
|---|---|---|---|
| 6 | User | **WALLED** | Enrollment = Domain Users and Client-Auth capable, but `ESS=False` → subject is built from the enrollee, so the SID extension binds the cert to **j.mercer**; it logs on as yourself. Closed by strong mapping. |
| 7 | EFS | **WALLED** | Enrollment = Domain Users, but EKU = Encrypting File System only — no logon EKU, so the cert cannot authenticate to AD. Closed by the EKU. |
| 8 | Machine | **WALLED** | Enrollment = Domain Computers / Admins; the foothold user is not in it. `ESS=False`. Closed by the enrollment DACL. |
| 9 | DomainController | **WALLED** | Enrollment = DCs / Admins; foothold not in it. (A *coerced DC account* enrolls this via the relay — that OPEN finding is the CA web-enrollment row, not this foothold path.) Closed by the enrollment DACL. |
| 10 | DomainControllerAuthentication | **WALLED** | Enrollment = DCs / Admins; foothold not in it. Closed by the enrollment DACL. |
| 11 | KerberosAuthentication | **WALLED** | Enrollment = DCs / Admins; `ESS=False`, subject is the authenticating machine. Closed by the enrollment DACL. |
| 12 | DirectoryEmailReplication | **WALLED** | Enrollment = DCs / Admins; EKU (DS Email Replication) is not a logon EKU. Closed by the enrollment DACL and EKU. |
| 13 | SubCA | **WALLED** | `ESS=True` (the abusable shape) **but** enrollment = Domain / Enterprise Admins; foothold cannot enrol. Closed by the enrollment DACL. |
| 14 | WebServer | **WALLED** | `ESS=True` but enrollment = Admins, and the Server Authentication EKU cannot client-auth. Closed by the enrollment DACL and EKU. |
| 15 | Administrator | **WALLED** | Enrollment = Admins; `ESS=False`. Closed by the enrollment DACL. |
| 16 | EFSRecovery | **WALLED** | Enrollment = Admins; File Recovery EKU is not a logon EKU. Closed by the enrollment DACL and EKU. |

## Disabled templates — **WALLED**, one shared dispositive fact

The following 22 were enumerated but each is `Enabled = False` (not published to
`Halstead-Root-CA`): the CA will not process a request for any of them, so no enrollment
path exists regardless of their flags — closed by publication state. `CA, CAExchange,
CEPEncryption, CTLSigning, ClientAuth, CodeSigning, CrossCA, EnrollmentAgent,
EnrollmentAgentOffline, ExchangeUser, ExchangeUserSignature, IPSECIntermediateOffline,
IPSECIntermediateOnline, KeyRecoveryAgent, MachineEnrollmentAgent, OCSPResponseSigning,
OfflineRouter, RASAndIASServer, SmartcardLogon, SmartcardUser, UserSignature, Workstation`.

## Summary

| Path | Observed condition | Verdict |
|---|---|---|
| HalsteadVPNAccess | `NoSecurityExtension` + writable `svc-scan` UPN | **OPEN** |
| HalsteadServiceCert | foothold Full-Control on the template object | **OPEN** |
| CA web enrollment | HTTP, no EPA — relay target | **OPEN** |
| HalsteadWorkstationEnroll | ESS + Client-Auth; PKINIT → object-SID mismatch | **WALLED** (strong mapping) |
| HalsteadMgrApproval | ESS + Client-Auth; `PendAllRequests` | **WALLED** (approval) |
| User | Client-Auth but `ESS=False` → maps to self | **WALLED** (strong mapping) |
| EFS | non-logon EKU | **WALLED** (EKU) |
| Machine, DomainController, DomainControllerAuthentication, KerberosAuthentication, DirectoryEmailReplication, SubCA, WebServer, Administrator, EFSRecovery | enrollment DACL excludes the foothold | **WALLED** (enrollment DACL) |
| 22 disabled templates | not published | **WALLED** (publication) |
| HalsteadCodeSign | ESS but Code-Signing-only EKU | **DECOY** |

## Key observation

Three enabled templates share the enrollee-supplies-subject condition, and each is decided
by a different control: **HalsteadWorkstationEnroll** by strong mapping (measured
`KDC_ERR_CLIENT_NAME_MISMATCH`), **HalsteadMgrApproval** by approval, **HalsteadCodeSign**
by a non-logon EKU. The single path enforcement does not reach is **HalsteadVPNAccess**,
whose `NoSecurityExtension` removes the SID field the wall depends on — which, with the
writable `svc-scan` UPN, is OPEN and begins the chain. The discipline is to separate these
by what the DC actually consults, not by how the template looks.
