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

For **every** path proved, three separate actions, stated the same way each time: the
**preventive control** that closes it, its **operational cost**, and the **already-issued
certificates to invalidate** (by serial — the authoritative revocation key; full serials in
§5.2). Then, in §3.2, the lasting effects that no template change touches.

### 3.1 Per proved path

**ESC8 — web-enrollment relay**
- **Preventive control:** enforce HTTPS + EPA (channel binding) on `/certsrv`; stop
  accepting NTLM there; require encrypted certificate requests at the CA; disable web
  enrollment if it is unused.
- **Operational cost:** one TLS certificate and an IIS reconfiguration on the single CA
  host; enrollment clients move to HTTPS. Low–moderate.
- **Certificates to invalidate:** the DC certificate — serial `…000012` (request 18,
  `halstead-dc01.pfx`). Its deeper residue is domain-wide, handled in §3.2.B.

**ESC9 — no SID extension + writable UPN**
- **Preventive control:** remove `CT_FLAG_NO_SECURITY_EXTENSION` from `HalsteadVPNAccess`
  (or, if interop genuinely requires it, use a strong explicit `altSecurityIdentities`
  mapping instead of implicit UPN); and remove the GenericWrite that lets a low-privilege
  account write `userPrincipalName` on `svc-scan`.
- **Operational cost:** review of any smartcard/VPN template that genuinely needs the flag,
  plus a directory-wide audit of write access to `userPrincipalName`. Low–moderate.
- **Certificates to invalidate:** the `pki.operator` certificate — serial `…00000F`
  (request 15, `pki.operator.pfx`), which is also the persistence certificate (§3.2.C). Also
  reset `pki.operator`'s password to a value of Halstead's choosing (the engagement reset
  it — §5.1).

**ESC4 — writable template**
- **Preventive control:** remove the Full-Control / Write-DACL / Write-Owner grants held by
  non-administrators on the `HalsteadServiceCert` template object.
- **Operational cost:** a single delegation correction. Minimal.
- **Certificates to invalidate:** the `helpdesk.svc` certificate — serial `…000011`
  (request 17, `helpdesk.svc.pfx`) — and the no-identity certificate issued before
  reconfiguration — serial `…000010` (request 16, `j.mercer.pfx`). The template itself is
  already restored and verified (§5.1).

**The wall already working — maintain, do not regress.**
- **Preventive control:** keep `StrongCertificateBindingEnforcement = 2` and the CA emitting
  the SID extension; keep the patch level that provides it.
- **Operational cost:** none beyond ordinary patch maintenance.
- **Certificates to invalidate:** the wall-test certificate — serial `…00000E` (request 14,
  `administrator.pfx`) — issued even though it could not authenticate.

### 3.2 Lasting effects beyond the per-path fixes

**A. Every certificate already issued.** None of the controls in §3.1 invalidates a
certificate that already exists; each stays valid on its own terms, for up to a year, and
keeps authenticating — including after any password reset. Revoke **all five** (§5.2) at the
CA by serial with reason *Key Compromise*, **publish an updated CRL immediately**, and
ensure the KDC performs revocation checking — a revocation sitting in an unread CA changes
nothing. Review `NTAuthCertificates` after revoking the DC-capable certificate.

**B. The domain is credential-compromised, not one-account-reset.** The relay chain ended in
**DCSync**, which replicates secrets out of the directory. Treat every privileged secret as
exposed: reset the **Administrator** password, reset **every account whose hash was
replicated**, and **rotate the `krbtgt` account twice** (replication exposes its key, which
enables forged tickets). A single password reset does not undo a DCSync — this is distinct
from, and additional to, revoking certificates.

**C. The persistence certificate specifically.** `pki.operator`'s certificate (serial
`…00000F`) authenticated *after* its password was reset and will keep doing so until it is
**revoked** and the CRL is published. Revocation — not the reset already performed — is what
ends that access.

The pattern across A–C: fixing *how* the certificates were obtained removes none of them.
The configuration was the door; the certificates are the keys already cut, and the
replicated hashes are the master copy — all keep working until explicitly revoked or
rotated.

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

### 5.2 Certificates issued — the complete set, revoke every one
This is the **exhaustive** list of certificates the engagement caused `Halstead-Root-CA` to
issue — five, no others. Each serial is read from the certificate itself (the `.pfx` on disk
is the evidence), so Halstead can revoke by serial directly, without matching on subject or
time. Revoke each with reason code *Key Compromise*, then publish the CRL.

| Req ID | Serial (revocation key) | Template | Identity in cert | File | Role |
|---|---|---|---|---|---|
| 14 | `180000000EFAEBF6026B153CEB00000000000E` | HalsteadWorkstationEnroll | SAN UPN `administrator` | `administrator.pfx` | wall-test — issued, cannot authenticate; revoke anyway |
| 15 | `180000000F6E914CFC8176A33500000000000F` | HalsteadVPNAccess | SAN UPN `pki.operator` | `pki.operator.pfx` | **the persistence certificate** — still authenticates after the password reset |
| 16 | `180000001063B22D7AB9E5352D000000000010` | HalsteadServiceCert | none (no SAN identity) | `j.mercer.pfx` | intermediate request before the template was reconfigured |
| 17 | `1800000011C49CD4BD847E5EEA000000000011` | HalsteadServiceCert | SAN UPN `helpdesk.svc` | `helpdesk.svc.pfx` | issued while the template was weakened |
| 18 | `18000000123A2A1AABDE0AB64A000000000012` | DomainController | `HALSTEAD-DC01$` (DC machine) | `halstead-dc01.pfx` | **DC-capable** — the certificate that reached the domain |

Nothing else was issued. The shadow credential used in ESC9 was an ephemeral Key Credential
written to `svc-scan` and already removed (§5.1); it was never a CA-issued certificate and
needs no revocation.

**Revocation priority:** serial `…000012` (DC, req 18) first, then `…00000F` (persistence,
req 15), then `…000011`, `…00000E`, `…000010`. Each of these authenticates — or, for the two
that cannot, still exists on the CA — until it is explicitly revoked and the CRL is
published; closing the templates does not close these.
