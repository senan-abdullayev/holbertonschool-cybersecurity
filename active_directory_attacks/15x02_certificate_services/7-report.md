# 7 — Engagement Report: Halstead Certificate Services (AD CS)

**Scope:** `halstead.local` — the enterprise CA `Halstead-Root-CA` on the member server
`HALSTEAD-CA01`, its templates, and the certificate-authentication path enforced by the
domain controller `HALSTEAD-DC01`.
**Starting position:** one low-privilege domain account, `halstead.local\j.mercer`.
**Outcome:** full domain compromise (Domain Admin) reached entirely through
certificate abuse, and demonstrated persistence that survives a password reset.

Halstead has done the hard part: strong certificate mapping is enforced and the naive,
best-known attack is genuinely dead here. This report is about the families that remained
open behind that wall, and — the part that outlasts this engagement — the certificates that
have already been issued.

---

## 1. The chain

### 1.1 Enumerate and triage (before touching anything)
From the foothold I enumerated every published template and the CA configuration. The CA
publishes 16 enabled templates; the decisive properties per template are **who may enrol**,
**whether the enrollee supplies the subject**, the **EKU**, **manager approval**, and
**whether the issued certificate carries the SID security extension**. At the CA level:
web enrollment is reachable over **plain HTTP with no EPA**; the user-specified-SAN flag is
**off** (no SAN injection); CA-officer rights are **admin-only**. At the DC:
`StrongCertificateBindingEnforcement = 2` and the CA stamps the requester SID into issued
certificates.

I split the surface into three verdicts:

| Verdict | Templates | What told me |
|---|---|---|
| **Walled** | `HalsteadWorkstationEnroll` (strong mapping), `HalsteadMgrApproval` (approval), all admin/DC-only defaults | enrollee-supplies-subject present, but a control closes it |
| **Open** | `HalsteadVPNAccess` (no SID extension), `HalsteadServiceCert` (writable object), CA web enrollment (relay) | the control that walls the others is absent here |
| **Decoy** | `HalsteadCodeSign` | enrollee-supplies-subject shape, but Code-Signing-only EKU — cannot authenticate |

### 1.2 The fork that mattered — proving the wall before trusting it
`HalsteadWorkstationEnroll` looks exactly like the classic subject-supply attack. Rather
than assume, I ran it: requested a certificate naming `administrator`, then attempted
PKINIT. The DC answered **`KDC_ERR_CLIENT_NAME_MISMATCH`**. That failure is a
specification: it says the DC consulted the **SID security extension**, that the extension
was **present**, and that it bound to the requester (`j.mercer`) — not to the name I
supplied. Strong mapping is live; the naive attack is dead. The same error told me exactly
where to look next: a template where that field is **not** present.

### 1.3 The path I correctly did not pursue
`HalsteadCodeSign` carries the enrollee-supplies-subject condition and will tempt the next
tester, but its EKU is Code Signing only — no certificate it issues can be used for
domain authentication, whatever subject is supplied. It is a decoy. I classified it, proved
the reasoning, and did not spend time trying to make it authenticate. `HalsteadMgrApproval`
is the same shape but closed by manager approval; also left alone. Naming these is part of
the finding: they are where an engagement loses a day.

### 1.4 The gap — impersonation where the SID is not stamped (ESC9)
`HalsteadVPNAccess` is configured with `CT_FLAG_NO_SECURITY_EXTENSION`, so its certificates
**omit** the SID extension; with nothing to bind on, the DC falls back to matching the
**UPN**. The foothold holds **GenericWrite** over the service account `svc-scan` — a UPN it
can write. I recovered `svc-scan`'s credential via shadow credentials
(`msDS-KeyCredentialLink`), set its UPN to `pki.operator`, enrolled `HalsteadVPNAccess`
**as `svc-scan`** (the issued certificate names `pki.operator`, no SID extension), reverted
the UPN, and authenticated by certificate as **`pki.operator`**. Supplying the name alone
would have mapped back to me; controlling the account the DC reads is what made the
difference.

### 1.5 The template I could rewrite (ESC4)
The foothold holds **Full Control** over the `HalsteadServiceCert` template object. Before
any change I exported the full configuration. I then reconfigured it to the exploitable
condition (enrollee-supplies-subject), enrolled as **`helpdesk.svc`**, authenticated, and
**restored the template to its exact prior state** — verified by re-exporting and diffing
against the pre-change capture (empty diff; see `4-restore.md`).

### 1.6 The bridge to the domain (ESC8 relay)
The CA's web enrollment is the one property SMB hardening cannot change: it accepts NTLM
over HTTP with no channel binding. I coerced the **DC machine account** (`HALSTEAD-DC01$`)
with PetitPotam (EFSRPC), relayed that authentication **cross-host** to the CA's web
enrollment, and obtained a certificate for the DC. Nothing about this certificate is a lie —
the machine really is the machine; I asked on its behalf. I then authenticated as
`HALSTEAD-DC01$`, recovered its hash, and used the DC's replication rights to **DCSync**
the `Administrator` hash — Domain Admin.

### 1.7 Persistence across a reset
Holding the `pki.operator` certificate, I let its password be reset, then authenticated
again. It still worked — covered in §3.

---

## 2. Impact

| Path | What it bought |
|---|---|
| ESC9 (`HalsteadVPNAccess` + writable UPN) | authentication as `pki.operator`, a privileged PKI account |
| ESC4 (`HalsteadServiceCert` writable) | authentication as `helpdesk.svc`, and the ability to mint a certificate for **any** principal by rewriting the template |
| ESC8 (web-enrollment relay) | a certificate for the DC machine account → **DCSync → Domain Admin** |
| Retained certificates | access that **survives password resets** for the certificate's full validity (1 year) |

**Why this is a critical, not a high.** Not because it reached Domain Admin — because of
what a certificate *is*. A certificate is an independently issued credential, valid on its
own terms for its full lifetime, that proves identity by private key through PKINIT and
**does not depend on the password at all**. It is a second, parallel proof of the same
identity. The standard first move of incident response — reset the compromised account's
password — rotates the Kerberos keys derived from the password and changes **nothing** the
certificate relies on. So this is not a foothold that a reset closes; it is a durable,
self-contained credential that the obvious remediation leaves fully intact. That property —
not the distance travelled — is what makes it critical.

---

## 3. Remediation

Each proved path needs **two** actions: **close it** so it cannot be used again, and **clean
the lasting effect** it already produced. The second half is the one that gets dropped in
the remediation meeting — and for certificate attacks it is the half that matters, because
closing a template does nothing to a certificate already issued or to credentials already
replicated out.

### 3.1 Per proved path — close it, and clean its residue

**ESC8 — web-enrollment relay.**
- *Close:* enforce **HTTPS + EPA (channel binding)** on `/certsrv`, stop accepting NTLM
  there, and require encrypted certificate requests on the CA; disable web enrollment
  entirely if it is unused. *Cost:* a TLS certificate and an IIS reconfiguration on the one
  CA host; enrollment clients move to HTTPS. Low–moderate, single server.
- *Clean:* revoke the DC certificate it produced (`halstead-dc01.pfx`, request 18). Its
  lasting effect is **not one certificate** — this path reached DCSync, so its residue is
  exposed domain credentials, handled in §3.2.B.

**ESC9 — no SID extension + writable UPN.**
- *Close:* remove `CT_FLAG_NO_SECURITY_EXTENSION` from `HalsteadVPNAccess` (or, if a genuine
  interop need requires it, replace implicit UPN mapping with an explicit **strong**
  `altSecurityIdentities` mapping); and remove the **GenericWrite** that let a low-privilege
  account write `userPrincipalName` on `svc-scan`. *Cost:* review of smartcard/VPN enrollment
  and of write access to `userPrincipalName` directory-wide. Low–moderate.
- *Clean:* revoke the `pki.operator` certificate (request 15), and **reset `pki.operator`'s
  password** to a value of Halstead's choosing (the engagement reset it — §5).

**ESC4 — writable template.**
- *Close:* remove the Full-Control / Write-DACL / Write-Owner grants held by
  non-administrators on the `HalsteadServiceCert` template object. *Cost:* a delegation
  correction, minimal.
- *Clean:* revoke the `helpdesk.svc` certificate (request 16) and the no-identity
  certificate issued in passing (`j.mercer.pfx`). The template itself is **already restored
  and verified** (§5).

**The wall already doing its job — keep it.** `StrongCertificateBindingEnforcement = 2` plus
the CA emitting the SID extension is what kills the classic attack; maintain full enforcement
and the patch level that provides the extension, and do not regress to compatibility mode.
*Clean:* revoke the wall-test certificate (request 13) — it was issued even though it could
not authenticate.

### 3.2 The lasting effects that outlive every fix above

**A. Every certificate already issued.** None of the controls in §3.1 invalidates a
certificate that exists; each remains valid on its own terms, for up to a year, and keeps
authenticating — including after any password reset. Revoke all five (§5) at the CA by
request ID / serial with reason *Key Compromise*, **publish an updated CRL immediately**,
and ensure the KDC performs revocation checking — a revocation sitting in an unread CA
changes nothing. Review `NTAuthCertificates` after revoking the DC-capable certificate.

**B. The domain is credential-compromised, not one-account-reset.** The relay chain ended in
**DCSync**, which replicates secrets out of the directory. Treat every privileged secret as
exposed: reset the **Administrator** password, reset **every account whose hash was
replicated**, and **rotate the `krbtgt` account twice** (replication exposes its key, which
enables forged tickets). A single password reset does not undo a DCSync — this is the action
that closes the domain-level residue, and it is distinct from revoking certificates.

**C. The persistence certificate specifically.** `pki.operator`'s certificate authenticated
*after* its password was reset and will keep doing so until it is **revoked** and the CRL is
published. Revocation — not the reset Halstead already performed — is what ends that access.

The pattern across A–C: fixing *how* the certificates were obtained does not remove the
certificates. The configuration was the door; the certificates are the keys that were cut,
and the replicated hashes are the master copy — all of them keep working until they are
explicitly revoked or rotated.

---

## 4. The wider surface — how to recognise exposure (a briefing, not findings)

The three paths in §1–§3 are this engagement's findings. This section is different in kind:
it is a briefing on the *conditions* that make any AD CS deployment exposed, so Halstead's
own team can triage the templates it adds later. It is deliberately **not** a list of named
attacks to memorise — the numbering in the public tooling grows and shifts as the tooling
does, while the conditions below do not. The durable capability is the triage, not the
catalogue.

A certificate becomes an escalation only when three things hold together: **a certificate
that can authenticate is reachable by someone who should not have it, and nothing binds the
certificate to its true requester.** Triage is checking, for every template and for the CA
and the DC, which of those three a control is actually closing. Four recognition dimensions
cover almost every case — read these rather than recall acronyms.

**Identity control — can the holder choose whom the certificate proves them to be?**
Recognise it by: the enrollee supplies the subject or SAN; the requester can influence the
UPN the certificate will carry; the issued certificate omits the SID security extension; or
the account is mapped by a weak, implicit identifier rather than a strong explicit one. When
the DC decides identity from a field the requester can influence, the template is exposed.
This is the condition strong mapping exists to close, and the one that was left open here.

**Enrollment rights — who can obtain an authentication-capable certificate at all?**
Recognise it by: broad or low-privilege principals holding enrol rights on any template
whose EKU permits logon — Client Authentication, Smart Card Logon, *Any Purpose*, or no EKU
at all. A template that cannot authenticate is never a path regardless of who may enrol; one
that can becomes a path the moment the wrong people can request it.

**Template and authority control — who can change the rules, or issue outside them?**
Recognise it by: write access (Full Control, Write-DACL, Write-Owner) over a template
object; control of the CA object, its configuration, or the `NTAuthCertificates` store; or
possession of the officer roles that approve and issue. A principal who can turn a safe
template into an unsafe one, or issue at will, holds the surface whatever the templates look
like today.

**Relay exposure — will an enrollment endpoint act on authentication that was not freely
given?** Recognise it by: an enrollment channel that accepts authentication without binding
it to the channel — web enrollment over HTTP or without EPA, or RPC enrollment without
request encryption — reachable by a privileged account that can be made to authenticate
outward. The hardening that protects file shares does not protect these endpoints; they are
checked separately.

Applied together across every template and the CA and DC, these four dimensions tell
Halstead whether a new template is a path **before** an attacker does. A template cloned
carelessly next quarter will not announce which condition it meets; reading these will.

---

## 5. Closeout

### 5.1 Template modified and restored
- **`HalsteadServiceCert`** was reconfigured (to enrollee-supplies-subject) and then
  **restored to its exact original configuration**. Verified: a fresh export after restore
  is **byte-identical** to the pre-change capture (`diff` empty). Original values include
  `msPKI-Certificate-Name-Flag = -2147483648`, `msPKI-Enrollment-Flag = 8`, `flags = 66106`.
  Full before/after in `4-restore.md`. No other template was changed.
- The `svc-scan` **shadow credential** (`msDS-KeyCredentialLink`) added during ESC9 was
  **removed** and its `userPrincipalName` **reverted** to `svc-scan@halstead.local`.

### 5.2 Certificates issued — revoke all of these
Revoke each at the CA by request ID / serial; the CA's issued-certificate database is the
authoritative source. Reason code: *Key Compromise*. Then publish the CRL.

| # | Template | Subject / identity | Request ID | File | Note |
|---|---|---|---|---|---|
| 1 | HalsteadWorkstationEnroll | UPN `administrator` | 13 | `administrator.pfx` | wall-test request; issued but non-authenticating — **still revoke** |
| 2 | HalsteadVPNAccess | UPN `pki.operator` | 15 | `pki.operator.pfx` | **live & used for persistence — highest urgency after the DC cert** |
| 3 | HalsteadServiceCert | UPN `helpdesk.svc` | 16 | `helpdesk.svc.pfx` | issued while template was weakened |
| 4 | HalsteadServiceCert | (no identity) | — | `j.mercer.pfx` | intermediate request before reconfiguration — revoke for completeness |
| 5 | DomainController | `HALSTEAD-DC01$` | 18 | `halstead-dc01.pfx` | **DC-capable — revoke first; review `NTAuthCertificates`** |

Shadow-credential certificates used in ESC9 were ephemeral Key Credentials on `svc-scan`,
already removed; they were never issued by the CA and need no revocation.

**Priority order for revocation:** #5 (DC) → #2 (persistence) → #3 → #1 → #4. A certificate
is a credential the domain will honour until it is revoked; closing the templates does not
close these.
