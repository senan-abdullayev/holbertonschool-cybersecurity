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

### 3.1 Per proved path — the control and its operational cost

- **ESC8 (web-enrollment relay).** Put **HTTPS + EPA (channel binding)** on `/certsrv` and
  stop accepting NTLM there; disable web enrollment entirely if it is not used. *Cost:*
  deploy a TLS certificate and reconfigure IIS on the one CA host; enrollment clients must
  move to HTTPS. Low–moderate, single server.
- **ESC9 (no SID extension + writable UPN).** Two parts: remove
  `CT_FLAG_NO_SECURITY_EXTENSION` from `HalsteadVPNAccess` unless a genuine interop need
  requires it (and if it does, use an explicit **strong** `altSecurityIdentities` mapping
  instead of implicit UPN); and remove the **GenericWrite** that lets a low-privilege
  account write `userPrincipalName` on `svc-scan`. *Cost:* review smartcard/VPN enrollment
  for templates that legitimately need the flag; audit write access to `userPrincipalName`
  across the directory. Low–moderate.
- **ESC4 (writable template).** Tighten the `HalsteadServiceCert` object DACL — remove the
  Full-Control / Write-DACL / Write-Owner grants held by non-administrators. *Cost:*
  minimal; a delegation correction.
- **The control already working — keep it.** `StrongCertificateBindingEnforcement = 2` plus
  the CA emitting the SID extension is exactly what walls the classic attack. Maintain full
  enforcement and the patch level that provides the extension; do not regress to
  compatibility mode.

### 3.2 Separately — the certificates that already exist
Every control above fixes *future* issuance. **None of them invalidates a certificate
already issued.** The certificates minted during this engagement remain valid on their own
terms until they expire (up to a year), and will continue to authenticate — including after
any password reset. Halstead must, as a distinct action:

1. **Revoke every certificate issued during the engagement** at the CA (by request ID /
   serial — see §5), with reason code *Key Compromise*.
2. **Publish an updated CRL immediately** (and ensure the KDC performs revocation checking)
   so the revocations take effect rather than sitting in a CA nobody reads.
3. For the **DC machine certificate** specifically, treat it as the highest priority: if any
   doubt remains about scope, consider rotating what the certificate ultimately exposed
   (the compromised account credentials via DCSync) and reviewing `NTAuthCertificates`.

This is the step that will not come up in the remediation meeting, because the instinct is
"we fixed the templates." The templates were only how the certificates were obtained; the
certificates are the access.

---

## 4. The wider surface (briefing)

I exploited three families here. Others exist on any AD CS deployment, and the point of
this section is **method, not catalogue** — the ESC numbers grow and renumber as tooling
evolves, so recognise families by their primitive, not by a memorised index.

Enumerate, for every template: **who may enrol**, **who supplies the subject/SAN**, the
**EKU**, **manager approval**, and **whether the SID extension is stamped** — and for the
CA: its **endpoints**, the **EDITF/attribute flags**, and the **officer ACLs** — then for
the DC: **how it maps a presented certificate**. A path is open when enrolment is reachable,
the certificate can authenticate, and nothing binds it to its true requester.

Families to recognise (not exploited here):

- **Attacker-controlled SAN at the CA** — a CA flag that lets any requester specify an
  arbitrary SAN on an otherwise-safe template. *Recognise:* the CA's attribute flags allow
  subject-alt-name in the request. Confirmed **off** here.
- **Over-permissive EKUs** — *Any Purpose* or no-EKU certificates that authenticate as the
  subject, or **Enrollment-Agent** certificates that let you enrol *on behalf of* others.
  *Recognise:* EKU = Any Purpose / Certificate-Request-Agent with low-privilege enrolment.
- **PKI-object and CA-officer control** — write access over the CA object, the templates
  container, `NTAuthCertificates`, or `ManageCA`/`ManageCertificates`. *Recognise:* ACLs on
  those objects granting non-admins. Confirmed admin-only here.
- **Mapping and policy weaknesses** — issuance policies that confer group membership, or
  application-policy / cross-mapping quirks. *Recognise:* templates linked to issuance
  policies, or mapping attributes set on accounts.

The durable skill is the triage above. Any one of these becomes the next engagement's foothold
the moment a template is cloned carelessly.

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
