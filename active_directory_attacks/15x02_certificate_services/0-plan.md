# 0 — The Plan, Against a Client Who Has Already Patched

## What I establish before I touch anything

I measure Halstead's posture on this domain controller, not the advisory default.
A read-only pass over the live PKI records, per template, enrollment rights, approval
flag, subject-supply flag, EKUs, and — decisively — whether the issued certificate
carries the SID security extension (szOID 1.3.6.1.4.1.311.25.2). Then I test enforcement:
I request from a template that *looks* like classic subject-supply and authenticate with
it. A KDC object-SID mismatch means strong mapping is live and that family
is walled here, on this DC — not merely "patched per the bulletin."

## The bar a path must clear, and what I write when it fails

A path enters my findings only when I have authenticated as the target identity and
confirmed it — ACL-gated proof read, or the reached principal shown — not on a
successful request. One template will look exactly like the famous technique;
recognising it is walled rather than burning the week is the discipline I commit to now. A path I cannot land I log as a hypothesis — expectation, failing step, the
enforcement that stopped it — never laundered into a finding.

## What I change, and how I prove I restored it

Every mutation to the CA or directory goes in a change register — one row per change,
written *before* I touch the object. Each row records the exact target (template or
account distinguished name; the specific attribute or permission, e.g.
`msPKI-Certificate-Name-Flag`, `nTSecurityDescriptor`, `userPrincipalName`,
`msDS-KeyCredentialLink`) and the captured original value, exported in full before
mutation. That capture is the rollback source, so no restore relies on memory.

After restoring, I prove it per item, not in bulk. For each row I do an independent
read-back — re-read the same attribute/ACL from the live object and compare it to the
pre-change capture — keeping both captures in `evidence/` as proof. Side effects are
reverted individually and checked the same way: each test certificate revoked and
confirmed revoked on the CA; each added UPN reset to its original string; each shadow
`msDS-KeyCredentialLink` entry removed and the attribute re-read to confirm it is empty.
No change is closed until its read-back matches its original capture.

## What the CA and DC will have on me

The CA will hold request/issuance records (4886/4887) tying each certificate to its
requester, and the DC the PKINIT authentications I performed. Fully attributable in both
logs — I plan cleanup, not concealment.
