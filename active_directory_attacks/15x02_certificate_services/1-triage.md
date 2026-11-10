# 1 — Reading the Certificate Authority

## Method

Enumerated as the foothold `halstead.local\j.mercer` only, no prior knowledge of which
template is which. Source: `certipy-ad find` (full output, 16 enabled templates), the
per-template fields (enrollment rights, name/enrollment flags, EKU, approval), the CA
configuration, and — where a verdict claims **open** or **walled** — an actual request +
PKINIT, because a verdict is a claim to be demonstrated, not asserted.

Three verdicts: **OPEN** (enforcement does not close it), **WALLED** (looks exploitable,
enforcement closes it), **DECOY** (looks like a known case but is neither — a day-waster).

## Authority (CA) configuration

| Property | Value | Consequence |
|---|---|---|
| Web Enrollment | **HTTP enabled, HTTPS disabled, no EPA** | **ESC8 — OPEN.** `/certsrv` is a relay target (plain HTTP, no channel binding). |
| User Specified SAN (`EDITF_ATTRIBUTESUBJECTALTNAME2`) | **Disabled** | **No ESC6.** The CA will not honour an attacker SAN on a non-ESS template. |
| ManageCA / ManageCertificates | Admins / Domain Admins / Enterprise Admins only | **No ESC7.** Foothold has no CA-officer rights. |
| Enroll (CA) | Authenticated Users | Normal. |
| KDC strong mapping | `StrongCertificateBindingEnforcement = 2`; CA stamps `szOID_NTDS_CA_SECURITY_EXT` | **Active.** A cert carries the requester's SID; the KDC binds on it, not on the SAN. |

## The template zoo — one entry per path

Only the five deliberate `Halstead*` templates carry a classifiable condition; the other
enabled templates are stock defaults (`User`, `Machine`, `DomainController`,
`WebServer`, `KerberosAuthentication`, …) with default ACLs and no enrollee-supplied
subject — **not exploitable from the foothold** (noted, closed).

### 1. HalsteadWorkstationEnroll — verdict: **WALLED** (by strong mapping)
- Fields: `Enrollee Supplies Subject = True`, Client Authentication EKU, no approval,
  enrollment = Domain Users. certipy tags **ESC1**.
- This is the template that looks exactly like the classic ESC1 everyone has read about.
  Task 0 committed to deciding by measurement, not assumption, whether strong mapping walls
  it. **Measured:**
  ```
  certipy req  ... -target HALSTEAD-CA01.halstead.local -template HalsteadWorkstationEnroll \
                   -upn administrator@halstead.local      -> cert issued (SID ext = j.mercer's SID)
  certipy auth -pfx administrator.pfx -dc-ip 10.20.0.10   -> KDC_ERR_CLIENT_NAME_MISMATCH
  ```
  The CA stamps the **requester's** SID (`szOID_NTDS_CA_SECURITY_EXT`, 1.3.6.1.4.1.311.25.2)
  into the cert. At PKINIT the KDC binds on that SID (j.mercer), not on the supplied
  `SAN UPN=administrator`, so the mismatch is rejected. The famous attack **fails**, and the
  error names the field the DC consulted (the SID extension) and confirms it was present.
  **Verdict: WALLED — enrollee-supplies-subject does not help you here.** Claiming it
  exploitable is a triage fault.

### 2. HalsteadVPNAccess — verdict: **OPEN** (ESC9)
- Fields: `Enrollment Flag = PublishToDs, NoSecurityExtension`, `Certificate Name Flag =
  SubjectAltRequireUpn`, Smart Card Logon + Client Authentication EKU, enrollment =
  Domain Users. certipy tags **ESC9 (no security extension)**.
- This is the gap. Because `NoSecurityExtension` is set, issued certs **omit** the SID
  extension — so the field the DC relied on to wall #1 is absent here, and the KDC falls
  back to UPN mapping. Load-bearing prerequisite confirmed: the foothold holds
  **GenericWrite over `svc-scan`** (BloodHound: `J.MERCER → svc-scan`), i.e. a settable UPN
  on a controllable account. **Verdict: OPEN** — write `svc-scan`'s UPN to the victim,
  enrol here, PKINIT as the victim. This is where #1's reasoning does not hold.

### 3. HalsteadServiceCert — verdict: **OPEN** (ESC4)
- Fields: `Enrollee Supplies Subject = False`, Client Authentication EKU, no approval.
  Not enrollable-to-abuse as-is — but the **object ACL** is the point: certipy tags
  **ESC4**, and `j.mercer` (Jordan Mercer) holds **Full Control / Write-Owner / Write-DACL**
  over the template. **Verdict: OPEN** — a template the foothold can rewrite into either of
  the exploitable conditions (ESS, or NoSecurityExtension), then must restore (Task 4).

### 4. HalsteadMgrApproval — verdict: **WALLED (by manager approval)** — a day-waster
- Fields: `Enrollee Supplies Subject = True` + Client Authentication EKU — i.e. **it looks
  exactly like ESC1** (same shape as #1). But `Enrollment Flag = PendAllRequests`
  (`Requires Manager Approval = True`). Every request pends for a CA officer and never
  auto-issues. Worth naming precisely because the next tester will burn time requesting
  through it and waiting. **Verdict: closed — not exploitable from the foothold.**

### 5. HalsteadCodeSign — verdict: **DECOY**
- Fields: `Enrollee Supplies Subject = True` (again, the ESC1 shape) but EKU = **Code
  Signing only** — `Client Authentication = False`, no Smart Card Logon. A cert from it
  cannot be used for Kerberos/PKINIT no matter what subject you supply. **Verdict: decoy —
  neither open nor a mapping wall; useless for authentication.**

## Summary

| Template | Looks like | Verdict | Why |
|---|---|---|---|
| HalsteadWorkstationEnroll | ESC1 | **WALLED** (strong mapping) | SID extension stamped (requester) → SID/UPN mismatch at PKINIT. |
| HalsteadVPNAccess | ESC9 | **OPEN** | `NoSecurityExtension` → no SID ext → UPN mapping + writable `svc-scan` UPN. |
| HalsteadServiceCert | ESC4 | **OPEN** | foothold has Full Control over the template object. |
| HalsteadMgrApproval | ESC1 | **WALLED** (approval) | `PendAllRequests` — never auto-issues. |
| HalsteadCodeSign | ESC1 | **DECOY** | Code-Signing EKU only — cannot authenticate. |
| CA web enrollment | ESC8 | **OPEN** | HTTP, no EPA — relay target. |
| stock defaults | — | closed | default ACLs, no enrollee subject. |

## Key observation

Three templates share the ESC1 "enrollee-supplies-subject" shape, and only one of the
three mapping conditions actually matters: **HalsteadWorkstationEnroll** is walled because
the CA stamps the requester SID and the KDC binds on it; **HalsteadMgrApproval** looks
identical but is closed by approval; **HalsteadCodeSign** is a decoy closed by EKU. The one
place the wall does **not** reach is **HalsteadVPNAccess**, where `NoSecurityExtension`
removes the very field the wall depends on — the gap that the rest of the chain is built
on. The discipline this triage proves is telling those four apart by what the DC actually
consults, not by how the template looks.
