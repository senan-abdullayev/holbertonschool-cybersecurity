# 1 — Reading the Certificate Authority

## Method

Enumerated as the foothold `halstead.local\j.mercer` only, no prior knowledge of which
template is which. Source: `certipy-ad find` (38 templates total, **16 enabled/published**
to `Halstead-Root-CA`), the per-template fields (enrollment rights, name/enrollment flags,
EKU, approval), the CA configuration, and — where a verdict claims **open** or **walled** —
an actual request + PKINIT, because a verdict is a claim to be demonstrated, not asserted.

Three verdicts, one per path: **OPEN** (enforcement does not close it), **WALLED** (looks
exploitable, enforcement closes it), **DECOY** (looks like a known case but is neither — a
day-waster). Only the **16 enabled** templates are live enrollment paths; the 22 disabled
ones are listed at the end with the single reason that disposes of them.

## Authority (CA) configuration

| Property | Value | Consequence |
|---|---|---|
| Web Enrollment | HTTP enabled, HTTPS disabled, no EPA | **ESC8 — OPEN.** `/certsrv` is a relay target (plain HTTP, no channel binding). |
| User Specified SAN (`EDITF_ATTRIBUTESUBJECTALTNAME2`) | Disabled | **No ESC6.** The CA will not honour an attacker SAN on a non-ESS template. |
| ManageCA / ManageCertificates | Admins / Domain Admins / Enterprise Admins only | **No ESC7.** Foothold has no CA-officer rights. |
| Enroll (CA) | Authenticated Users | Normal. |
| KDC strong mapping | `StrongCertificateBindingEnforcement = 2`; CA stamps `szOID_NTDS_CA_SECURITY_EXT` | Active. A cert carries the requester's SID; the KDC binds on it, not on the SAN. |

## Custom templates (the deliberate zoo) — one entry per path

### 1. HalsteadWorkstationEnroll — verdict: **WALLED** (by strong mapping)
- Fields: `Enrollee Supplies Subject = True`, Client Authentication EKU, no approval,
  enrollment = Domain Users. certipy tags **ESC1**.
- The template that looks exactly like classic ESC1. Decided by measurement:
  ```
  certipy req  ... -target HALSTEAD-CA01.halstead.local -template HalsteadWorkstationEnroll \
                   -upn administrator@halstead.local      -> cert issued (SID ext = j.mercer's SID)
  certipy auth -pfx administrator.pfx -dc-ip 10.20.0.10   -> KDC_ERR_CLIENT_NAME_MISMATCH
  ```
  The CA stamps the **requester's** SID (`szOID_NTDS_CA_SECURITY_EXT`, 1.3.6.1.4.1.311.25.2).
  At PKINIT the KDC binds on that SID (j.mercer), not on the supplied `SAN UPN=administrator`,
  so it is rejected. The famous attack **fails**, and the error names the field consulted
  (the SID extension) and confirms it was present. **WALLED — ESS does not help here;
  claiming it exploitable is a triage fault.**

### 2. HalsteadVPNAccess — verdict: **OPEN** (ESC9)
- Fields: `Enrollment Flag = PublishToDs, NoSecurityExtension`, `Name Flag =
  SubjectAltRequireUpn`, Smart Card Logon + Client Authentication EKU, enrollment = Domain
  Users. certipy tags **ESC9**.
- `NoSecurityExtension` means issued certs **omit** the SID extension — the field that walls
  #1 is absent here, so the KDC falls back to UPN mapping. Prerequisite confirmed: foothold
  holds **GenericWrite over `svc-scan`** (BloodHound `J.MERCER → svc-scan`), a settable UPN
  on a controllable account. **OPEN** — set `svc-scan`'s UPN to the victim, enrol here,
  PKINIT as the victim. This is where #1's reasoning does not hold.

### 3. HalsteadServiceCert — verdict: **OPEN** (ESC4)
- Fields: `Enrollee Supplies Subject = False`, Client Authentication EKU, no approval. Not
  abusable as configured — but the **object ACL** is: certipy tags **ESC4**, and `j.mercer`
  holds **Full Control / Write-Owner / Write-DACL** over the template. **OPEN** — rewrite it
  into an exploitable condition, enrol, then restore (Task 4).

### 4. HalsteadMgrApproval — verdict: **WALLED (manager approval)** — a day-waster
- Fields: `Enrollee Supplies Subject = True` + Client Authentication EKU — **identical shape
  to #1 (ESC1)**. But `Enrollment Flag = PendAllRequests` (`Requires Manager Approval =
  True`): every request pends for a CA officer and never auto-issues. Named precisely
  because the next tester will burn time here. **Closed — not exploitable from the foothold.**

### 5. HalsteadCodeSign — verdict: **DECOY**
- Fields: `Enrollee Supplies Subject = True` (ESC1 shape again) but EKU = **Code Signing
  only** — `Client Authentication = False`, no Smart Card Logon. The cert cannot be used for
  Kerberos/PKINIT whatever subject you supply. **Decoy — neither open nor a mapping wall.**

## Default enabled templates — one verdict per path

All stock; none has an attacker-usable condition. Two (`EFS`, `User`) are enrollable by the
foothold and are closed on their merits, not merely by ACL.

| # | Template | Foothold can enrol? | Verdict | Reason (evidence) |
|---|---|---|---|---|
| 6 | User | **Yes** (Domain Users) | **CLOSED** | Client-Auth EKU, but `ESS=False` → subject built from the enrollee; SID extension binds the cert to **j.mercer**, so it authenticates as yourself. No escalation (the "maps back to you" baseline). |
| 7 | EFS | **Yes** (Domain Users) | **CLOSED** | `ESS=False`; EKU = Encrypting File System only — no Client Auth / Smart Card Logon, so the cert cannot authenticate to AD. |
| 8 | Machine | No (Domain Computers/Admins) | **CLOSED** | Foothold is a user, not a computer; no enrolment right. `ESS=False`, SID-bound subject. |
| 9 | DomainController | No (DCs/Admins) | **CLOSED** (direct) | Foothold has no enrolment right. Note: this is the template the **ESC8 relay** enrols *as the coerced DC$* (the DC is in the enrol set) — abused via ESC8, not via foothold enrolment. |
| 10 | DomainControllerAuthentication | No (DCs/Admins) | **CLOSED** (direct) | As #9 — no foothold enrolment; a secondary ESC8 relay target for the DC machine account. |
| 11 | KerberosAuthentication | No (DCs/Admins) | **CLOSED** | No foothold enrolment right; `ESS=False`, subject is the authenticating machine. |
| 12 | DirectoryEmailReplication | No (DCs/Admins) | **CLOSED** | No foothold enrolment right; EKU (DS Email Replication) is not a logon EKU. |
| 13 | SubCA | No (Domain/Enterprise Admins) | **CLOSED** | `ESS=True` (ESC1-shaped) **but** enrolment restricted to admins — foothold cannot enrol. |
| 14 | WebServer | No (Domain/Enterprise Admins) | **CLOSED** | `ESS=True` but admins-only enrolment, and Server Authentication EKU cannot client-auth. |
| 15 | Administrator | No (Domain/Enterprise Admins) | **CLOSED** | Admins-only enrolment; `ESS=False`. Foothold cannot enrol. |
| 16 | EFSRecovery | No (Domain/Enterprise Admins) | **CLOSED** | Admins-only enrolment; File Recovery EKU is not an auth EKU. |

## Disabled templates (not a live path)

**CLOSED — not published to `Halstead-Root-CA` (`Enabled = False`), so no enrolment path
exists regardless of their flags.** The 22: `CA, CAExchange, CEPEncryption, CTLSigning,
ClientAuth, CodeSigning, CrossCA, EnrollmentAgent, EnrollmentAgentOffline, ExchangeUser,
ExchangeUserSignature, IPSECIntermediateOffline, IPSECIntermediateOnline, KeyRecoveryAgent,
MachineEnrollmentAgent, OCSPResponseSigning, OfflineRouter, RASAndIASServer, SmartcardLogon,
SmartcardUser, UserSignature, Workstation`.

## Summary

| Path | Looks like | Verdict | Why |
|---|---|---|---|
| HalsteadWorkstationEnroll | ESC1 | **WALLED** (strong mapping) | requester-SID stamped → SID/UPN mismatch at PKINIT. |
| HalsteadVPNAccess | ESC9 | **OPEN** | `NoSecurityExtension` → no SID ext → UPN mapping + writable `svc-scan` UPN. |
| HalsteadServiceCert | ESC4 | **OPEN** | foothold Full Control over the template object. |
| HalsteadMgrApproval | ESC1 | **WALLED** (approval) | `PendAllRequests` — never auto-issues. |
| HalsteadCodeSign | ESC1 | **DECOY** | Code-Signing EKU — cannot authenticate. |
| CA web enrollment | ESC8 | **OPEN** | HTTP, no EPA — relay target. |
| User, EFS (defaults) | — | **CLOSED** | enrollable but self-mapped (User) or non-auth EKU (EFS). |
| Machine, DomainController(+Auth), KerberosAuthentication, DirectoryEmailReplication, SubCA, WebServer, Administrator, EFSRecovery | — | **CLOSED** | no foothold enrolment right (see table). |
| 22 disabled templates | — | **CLOSED** | not published to the CA. |

## Key observation

Three enabled templates share the ESC1 "enrollee-supplies-subject" shape, and the three
possible closing mechanisms are each represented: **HalsteadWorkstationEnroll** is walled by
strong mapping (requester SID), **HalsteadMgrApproval** by approval, **HalsteadCodeSign** by
EKU. The one place the wall does **not** reach is **HalsteadVPNAccess**, where
`NoSecurityExtension` removes the field the wall depends on — the gap the rest of the chain
is built on. The discipline this triage proves is separating those paths by what the DC
actually consults, not by how the template looks.
