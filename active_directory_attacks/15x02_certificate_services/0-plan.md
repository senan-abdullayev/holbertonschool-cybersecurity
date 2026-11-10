# 0 — The Plan, Against a Client Who Has Already Patched

## What I establish before I touch anything

I do not assume Halstead's posture from the advisory default. I measure it on this
domain controller. First I enumerate the live PKI with a read-only pass against the
CA and templates, recording for each template the enrollment rights, the manager-
approval flag, whether the enrollee supplies the subject, the EKUs, and — decisively —
whether the issued certificate carries the SID security extension (szOID
1.3.6.1.4.1.311.25.2). Then I test enforcement empirically: I request a certificate
from a template that *looks* like the classic subject-supply case and attempt
certificate-based authentication with it. If the KDC rejects it with an object-SID
mismatch, strong certificate mapping is live and that family is walled here, on this
DC — not "probably patched per the bulletin." That rejection is the ground truth I
build the rest of the engagement on.

## The bar a path must clear, and what I write when it fails

A path enters my findings only when I have authenticated as the target identity and
confirmed it — read the ACL-gated proof, or shown the reached principal — not because
a request returned success. At least one template here will look exactly like the
famous technique everybody knows; recognising that it is walled, and refusing to spend
the week on it, is the discipline I commit to now. A path I believe exists but cannot
land I record separately as a hypothesis: what I expected, the exact step that failed,
and the enforcement that stopped it. I do not launder a plausible idea into a
confirmed finding.

## What I change, and how I prove I restored it

Any template I reconfigure to exploit it, I snapshot first (full configuration export)
and restore to that exact state afterward, then re-read it to prove the restore landed.
Issued test certificates and any UPN or shadow-credential changes are reverted as part
of the workflow. Hardened templates leave the engagement hardened.

## What the CA and DC will have on me

By the end, the CA will hold request and issuance records (events 4886/4887) tying
every certificate to the requesting account, and the DC will hold the PKINIT
authentications I performed. I expect to be fully attributable in both logs — I plan
the cleanup, not the concealment.
