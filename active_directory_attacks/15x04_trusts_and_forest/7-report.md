# Aldermont Holdings — Active Directory Trust & Forest Assessment

**Client:** Aldermont Holdings
**Scope:** The Aldermont Active Directory estate — `aldermont.local` (forest root), `corp.aldermont.local` (regional child), and the acquired forest `trentham.local`, joined by a forest trust.
**Starting position (as agreed):** one regional administrator account (`r.bello`, administrator of `corp.aldermont.local`). No software vulnerabilities were used at any point in this assessment.
**Outcome:** From that single regional-admin account we obtained full control of the forest root and read a protected resource inside the separately-owned Trentham forest. Both results follow from how your trusts are configured, not from any flaw in your software.

---

## 1. The estate — what you actually have

Aldermont is not one network. It is **three directories that agreed to trust each other**, and those agreements are the real map of your attack surface:

- **`aldermont.local` — the forest root.** The top of the house. Whoever controls it controls everything beneath it.
- **`corp.aldermont.local` — the regional child.** Run by a separate team, with its own administrators and its own change control. On every diagram there is a line between it and the root.
- **`trentham.local` — a company you acquired.** A *separate* directory ("forest") of its own, bolted onto Aldermont three years ago by a trust so the two could share resources.

Two trust relationships hold this together:

| Trust | Between | What it is |
|-------|---------|-----------|
| **A** | `corp` ⇄ `aldermont` | the normal parent/child link **inside one forest** |
| **B** | `aldermont` ⇄ `trentham` | a **forest-to-forest** link between two separate companies |

**What is reachable from where (plain language).** The regional team's administrator can, by design and with no exploit, become administrator of the entire forest root — the line on your diagram between "corp" and "the root" is a drawing, not a wall. The forest link to Trentham behaves differently: it **blocks** an attacker who tries to fake a Trentham identity, but it still **honours a real permission** that was granted to an Aldermont group during the acquisition and never removed. So Trentham is protected against forgery but not against a forgotten grant.

The one sentence to circulate internally:

> **The regional child domain was compromised, and the forest root fell as a direct consequence — with no vulnerability anywhere. Running the two domains as separate teams with separate change control did not make them separate security zones.**

---

## 2. What crossed — the chain, boundary by boundary

Each step below ends at a *boundary*, and the interesting part is the **decision** the boundary made.

1. **Foothold.** We began as `r.bello`, administrator of the regional child `corp.aldermont.local`. *(Provided; not attacked.)*
2. **Took the child's master key.** As the child's administrator we copied the child domain's Kerberos signing key (a `krbtgt` replication / "DCSync"). This is a normal administrative capability inside the child.
3. **Minted a pass carrying a second identity.** We built a Kerberos ticket for the child that *also* carried the identity of the root's **Enterprise Admins** group alongside our own. A ticket is allowed to carry extra identities — this exists so a multi-domain forest can function.
4. **Boundary A → it crossed.** We presented that ticket to the forest root. **Decision: the forest root did not check.** Inside a single forest, identities travelling between domains are **not filtered**, so the injected Enterprise-Admins identity was accepted. We became forest-root administrator and read the two root-only resources that `r.bello` is explicitly denied (`C:\RootOnly\intraforest.txt`, `C:\RootOnly\root.txt`).
5. **Boundary B → it did NOT cross (and this matters more than the successes).** We deliberately pointed the *same* technique at Trentham, injecting a Trentham administrator identity. **Decision: the forest edge removed it before Trentham ever considered it.** The forest trust filters out any identity that (a) belongs to a forest other than the trusted one, or (b) is a built-in high-privilege identity. Our injected identity was both, so it was stripped and the attempt failed. **We did not reach Trentham by this path, and we are not reporting that we did.** *This is the boundary of yours that is working.*
6. **Boundary B → the door that does open.** Returning to the trust map, we found **`LegacyAcq`** — an Aldermont group labelled *"Acquisition-era cross-forest access (leftover)"* that still holds read rights on Trentham's protected `crown` share. Because this group is a **genuine Aldermont identity** (not a forgery) it passes the filter, and because it was **granted a real permission** in Trentham, membership grants access. We added our controlled account to it, authenticated into Trentham the legitimate way, and read `\\TRENTHAM-DC\crown\crownjewel.txt`. We then removed the membership (see Closeout).
7. **The migration leftover.** Separately we confirmed the intra-forest **account-history ("SID history")** mechanism — the feature that lets migrated accounts keep their old access — is honoured inside the forest and would carry a privileged identity from child to root exactly as step 4 did. It is **neutralised at the Trentham edge** by the same filter as step 5.

---

## 3. The two boundaries — the part that changes your architecture

This is the conceptual payload. It changes how you draw your diagrams, not which boxes you tick.

**Why the child domain is *not* a security boundary.** A trust inside a single forest does **nothing** to an identity travelling across it — no filtering, no inspection. An identity minted in `corp` arrives at the root with full force. Therefore *anyone who fully controls the child already controls the root*; the separation between the two teams is **administrative**, not a security barrier. Treat the entire forest as one blast radius: a compromise anywhere in `aldermont.local`/`corp.aldermont.local` is a compromise of the whole forest.

**Why the forest edge *mostly* is a boundary.** A forest trust **does** act on identities crossing it. It enforces two independent rules:
- it **drops identities from any other forest** (an account forest may only speak for its own forest's identities), and
- it **drops built-in high-privilege identities** (the reserved low-numbered ones) even from the trusted forest.
Those two rules are why the injection in step 5 failed — and why they are categorically different from the inside-the-forest case. The edge is "mostly" a boundary, not fully, for one reason: it still honours a **real, native Aldermont group that was legitimately granted access** (step 6). The filter stops forgery; it cannot stop a permission you actually gave and forgot. **So the forest is close to a true boundary — provided your cross-forest grants are clean.**

---

## 4. Detection and remediation

**What each step wrote to your logs** (these are the records a monitoring team would key on):

| Step | Record on the DC |
|------|------------------|
| Copying the child key (step 2) | Directory replication access — **Event 4662** (replication of secrets) from a non-DC source |
| Using the forged/elevated ticket (steps 3–4) | **4768 / 4769** Kerberos ticket requests, with anomalous group content |
| The failed Trentham injection (step 5) | Cross-realm **4769** failures / ticket rejection at the edge |
| Adding our account to `LegacyAcq` (step 6) | **Event 4756** — a member was added to a security-enabled *universal* group |
| Authenticating into Trentham (step 6) | **4768 / 4624** on `TRENTHAM-DC` for a foreign principal |
| Writing account history (step 7) | **Event 4765 — "SID History was added to an account"** (a failed attempt is **4766**) |

The standout is **4765**: adding account history is a directory modification and one of the very few actions here a competent team would notice **the same day** — *if* the "Audit User Account Management" policy is enabled and someone is alerting on it. Aldermont did not see it because that auditing/alerting is not in place; the records are writable but nobody is reading them.

**The specific control that closes each path:**

- **Boundary A (child → root).** This cannot be "patched" — it is how forests work. The control is **containment**: treat the whole forest as one trust zone, hold child-domain administrators to the same standard as Enterprise Admins, protect the `krbtgt` keys (and rotate them twice), and tier your administration so a regional admin account is not a forest-ending event.
- **Boundary B — the acquired trust.** The filtering is doing its job; the exposure is the **leftover grant**. Remove `LegacyAcq`'s access to the Trentham `crown` resource (and audit every other Aldermont group or foreign principal that holds rights inside Trentham). For a stricter posture, enable **selective authentication** on the forest trust so Aldermont principals can reach a Trentham resource only where Trentham has *explicitly* allowed it.
  - **What that stricter posture costs Trentham:** selective authentication is not free. Every legitimate cross-forest access must be granted per-resource ("Allowed to authenticate"); anything today relying on blanket forest-wide access breaks until re-permitted, and Trentham's admins carry the ongoing overhead of maintaining that list. It is the correct trade, but it is an operational commitment, not a checkbox.
- **The migration artefact (account history).** Account history should have been **cleared once the migration completed years ago** — it is a transitional feature, not a permanent one. Sweep for and remove stray `sIDHistory` values, and turn on the 4765/4766 auditing above so the next one is caught the day it is written.

---

## 5. The wider surface — what Aldermont should assess next

We exercised the trust paths our scope covered. The following are *additional* trust-abuse avenues we did **not** test and that Aldermont should have assessed — listed as gaps in your assurance, not as a to-do list of attacks:

- **Delegation reachable across a trust.** Kerberos delegation (unconstrained, constrained, resource-based) that spans a trust can turn a foothold on one side into authentication on the other. *(The estate contained a deliberate unconstrained-delegation decoy; real delegation across your trusts deserves a proper review.)*
- **Coercion across a trust.** Techniques that *force* a server or DC to authenticate to an attacker (printer/EFS-style coercion) can pull privileged authentication across a trust boundary. Assess which of your machines can be coerced and where that authentication can land.
- **Group memberships held by foreign principals.** `LegacyAcq` was one forgotten grant; a full inventory of **every** cross-forest and foreign-security-principal membership in both directories is the single highest-value hygiene task to come out of this report.
- **The forest-to-cloud boundary.** The most important trust edge most organisations now own is the one between Active Directory and a **cloud identity provider** (Entra ID / federation / directory sync). Compromise of the on-premises forest very often extends to the cloud tenant through that connector. This is where this class of attack is heading, and it should be in scope for your next assessment.

---

## 6. Closeout — what we changed and the evidence it is gone

We committed to minimal, reversible changes and to proving removal.

**Directory modifications made during this engagement:**

| # | Directory | Object | Change | Reverted? |
|---|-----------|--------|--------|-----------|
| 1 | `aldermont.local` | `CN=LegacyAcq,CN=Users,DC=aldermont,DC=local` | added member `CN=r.bello,…,DC=corp,…` to open the Trentham door (step 6) | **Yes** |

- **Before state (captured first):** `LegacyAcq` had **no members**.
- **After the engagement:** the member was removed and the group **re-read** independently — it is **empty again**, matching the original state. (Any account history written while demonstrating step 7 is likewise removed and read back empty; account history is a persistent attribute and was not left in place.)
- **No other persistence:** no accounts were created, no Kerberos tickets or keys were left on any system, and no `krbtgt` or other secret was altered. The forged tickets used were held only on the testing host and are disposable.

Nothing we introduced remains in either directory. The one artefact we did **not** create but which *was already present* — the `LegacyAcq` grant into Trentham — is the item we recommend Aldermont remove (Section 4).

---

*Evidence (ticket/PAC captures, the filter diagnosis, the cross-forest read, and the before/after group-membership read-backs) is retained in the engagement `evidence/` directory and available on request.*
