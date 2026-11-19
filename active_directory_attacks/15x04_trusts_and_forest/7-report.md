# Aldermont Holdings — Active Directory Trust & Forest Assessment

**Client:** Aldermont Holdings
**Scope:** The Aldermont Active Directory estate — `aldermont.local` (forest root), `corp.aldermont.local` (regional child), and the acquired forest `trentham.local`, joined by a forest trust.
**Starting position (as agreed):** one regional administrator account (`r.bello`, administrator of `corp.aldermont.local`). No software vulnerabilities were used at any point in this assessment.
**Outcome:** From that single regional-admin account we obtained full control of the forest root and read a protected resource inside the separately-owned Trentham forest. Both results follow from how your trusts are configured, not from any flaw in your software.

---

> **How to read this report.** Section 1 is the plain-language summary written for circulation
> to any reader — no technical background needed. Sections 2–6 are written for the Active
> Directory team and necessarily use the exact technical terms, events, and commands those fixes
> require.

## 1. The estate — what you actually have

Aldermont is not one network. It is **three separate directories that agreed to trust each other.** Those agreements — not the network diagram — are the real map of who can reach what. Here is the whole estate on one picture:

```
        ALDERMONT  (the parent company directory)
        aldermont.local  — the top of the house
              |
              |  Trust A: parent & child, SAME company directory
              |           (no gate between them)
              |
        CORP   (a regional branch, run by a different team)
        corp.aldermont.local   <-- our starting account lives here

        ALDERMONT  <===========>  TRENTHAM   (a company Aldermont bought)
                   Trust B: two                trentham.local
                   DIFFERENT company
                   directories, linked
                   (this link has a gate)
```

The three directories, in plain terms:

- **`aldermont.local` — the head office directory.** The top of the house. Whoever controls it controls everything beneath it.
- **`corp.aldermont.local` — a regional branch.** The same company as head office, just run by a different team with its own admins. This is where our starting account sits.
- **`trentham.local` — a company Aldermont acquired.** A genuinely *separate* company's directory, connected to Aldermont three years ago so the two could share resources.

Two links hold it together:

| Link | Between | In plain terms |
|------|---------|----------------|
| **Trust A** | `corp` ⇄ `aldermont` | branch ↔ head office — **the same company's directory**, with no gate between them |
| **Trust B** | `aldermont` ⇄ `trentham` | Aldermont ↔ an **acquired, separate company**, with a gate on the link |

**Who can reach what (this is the part that matters):**

| Starting point | Can they reach… | Result | Why |
|----------------|-----------------|--------|-----|
| the **branch** admin (our account) | **head office** (the root) | **Yes — total control** | there is **no gate** between a branch and head office; an identity made in the branch is accepted at head office unchanged |
| the **branch/head-office** side | **Trentham**, by faking a Trentham identity | **No** | the gate on Trust B **throws out faked identities** before Trentham ever sees them |
| the **branch/head-office** side | **Trentham**, using a *real* leftover permission | **Yes** | one Aldermont group was given real access inside Trentham during the acquisition and never un-granted; the gate lets a *genuine* permission through |

In one line: **head office is wide open from the branch, and Trentham is protected against forgery but not against a forgotten permission.**

The one sentence to circulate internally:

> **The regional branch was compromised, and head office fell as a direct consequence — with no software flaw anywhere. Running the branch and head office as separate teams with separate change control did not make them separate security zones.**

---

## 2. What crossed — the chain, boundary by boundary

Every boundary we reached is below, and for each we record whether it **let us through** or **stopped us** — a chain that only listed wins would hide which of your boundaries are actually working.

**Boundary outcomes at a glance (both the successes and the block):**

| Boundary | What we tried | Outcome | Why |
|----------|---------------|---------|-----|
| **Trust A** — branch → head office | carry an injected head-office admin identity across | ✅ **CROSSED** | no gate inside one company's directory — the injected identity was accepted unchanged |
| **Trust B** — head office → Trentham (by forgery) | carry an injected Trentham admin identity across | ⛔ **BLOCKED** | the gate stripped the faked identity before Trentham saw it — *this boundary is doing its job* |
| **Trust B** — head office → Trentham (the real door) | use a genuine leftover group permission | ✅ **CROSSED** | the gate passes a *real* permission; the leftover grant let us in |

The blocked row is the most important line in this report: it is the one boundary of yours that held, and we are **not** claiming we crossed it. The step-by-step below shows the decision each boundary made.

Each step below ends at a *boundary*, and the interesting part is the **decision** the boundary made.

1. **Foothold.** We began as `r.bello`, administrator of the regional child `corp.aldermont.local`. *(Provided; not attacked.)*
2. **Took the child's master key.** As the child's administrator we copied the child domain's Kerberos signing key (a `krbtgt` replication / "DCSync"). This is a normal administrative capability inside the child.
3. **Minted a pass carrying a second identity.** We built a Kerberos ticket for the child that *also* carried the identity of the root's **Enterprise Admins** group alongside our own. A ticket is allowed to carry extra identities — this exists so a multi-domain forest can function.
4. **Boundary A → it crossed.** We presented that ticket to the forest root. **Decision: the forest root did not check.** Inside a single forest, identities travelling between domains are **not filtered**, so the injected Enterprise-Admins identity was accepted. We became forest-root administrator and read the two root-only resources that `r.bello` is explicitly denied (`C:\RootOnly\intraforest.txt`, `C:\RootOnly\root.txt`).
5. **Boundary B → it did NOT cross (and this matters more than the successes).** We deliberately pointed the *same* technique at Trentham, injecting a Trentham administrator identity. **Decision: the forest edge removed it before Trentham ever considered it.** The forest trust filters out any identity that (a) belongs to a forest other than the trusted one, or (b) is a built-in high-privilege identity. Our injected identity was both, so it was stripped and the attempt failed. **We did not reach Trentham by this path, and we are not reporting that we did.** *This is the boundary of yours that is working.*
6. **Boundary B → the door that does open.** Returning to the trust map, we found **`LegacyAcq`** — an Aldermont group labelled *"Acquisition-era cross-forest access (leftover)"* that still holds read rights on Trentham's protected `crown` share. Because this group is a **genuine Aldermont identity** (not a forgery) it passes the filter, and because it was **granted a real permission** in Trentham, membership grants access. We added our controlled account to it, authenticated into Trentham the legitimate way, and read `\\TRENTHAM-DC\crown\crownjewel.txt`. We then removed the membership (see Closeout). **Why this crossed where step 5 did not, stated exactly:** the forest trust behaved precisely as designed. It did not pass a forgery or a ticket — it passed a **genuine Aldermont security principal (`LegacyAcq`) carrying a real, administratively-granted permission** on the Trentham `crown` resource. SID filtering **passes legitimate authority and strips forged or foreign authority**, so this crossing turned entirely on the existence of that real leftover grant — not on reachability to TRENTHAM-DC and not on the earlier ticket forging, neither of which changes the trust's filtering decision.
7. **(Not a boundary crossing — an aside.)** Separately from the chain above, we exercised the intra-forest **account-history (`sIDHistory`)** mechanism. It belongs to **Boundary A's** category, never Boundary B's: it is honoured **unchanged inside the forest** (the same reason step 4 crossed) and is **stripped at the Trentham edge** (the same filter that blocked step 5). It therefore **crossed no new boundary and reached nothing inside Trentham** — it is only an *alternative* route to the same forest-root result already achieved in step 4, not a separate conquest and not a Trentham crossing. Its detection record and its closeout (the write and its reversal) are in §4 and §6; we keep it out of the numbered crossings precisely so the single blocked boundary (step 5) and the single genuine Trentham crossing (step 6) stay unambiguous.

**Two Trentham routes — do not conflate them.** Exactly **one** technique crossed into Trentham, and it was **not** an injected identity. The two injection routes — the forged Trentham-admin ticket (step 5) and the intra-forest `sIDHistory` demonstration (step 7) — **both failed at the forest edge** and reached nothing inside Trentham. The **only** successful Trentham crossing was **step 6**, the genuine `LegacyAcq` grant. So the injected-identity chain (steps 3–5 and 7) succeeded **only** against the forest root — Boundary A, inside one forest — and was stopped cold at Boundary B. We are not claiming, anywhere, that a forged or SID-history identity reached Trentham.

---

## 3. The two boundaries — the part that changes your architecture

This is the conceptual payload. It changes how you draw your diagrams, not which boxes you tick.

**Why the child domain is *not* a security boundary.** A trust inside a single forest does **nothing** to an identity travelling across it — no filtering, no inspection. The identity and authorization data carried in the ticket (the **PAC** — its SIDs, including any SID-history) is accepted **as presented**; nothing strips it. That is the precise mechanism: because a child's authorization data is honoured unchanged at the root, *anyone who fully controls the child already controls the root*, and the separation between the two teams is **administrative**, not a security barrier. Treat the entire forest as one blast radius: a compromise anywhere in `aldermont.local`/`corp.aldermont.local` is a compromise of the whole forest.

**Why the forest edge *mostly* is a boundary.** A forest trust **does** act on identities crossing it. It enforces two independent rules:
- it **drops identities from any other forest** (an account forest may only speak for its own forest's identities), and
- it **drops built-in high-privilege identities** (the reserved low-numbered ones) even from the trusted forest.
This is the **SID filtering / SID-history treatment** applied at the trust: it strips SIDs foreign to the trusted forest, and built-in high-privilege (RID<1000) SIDs, out of the incoming PAC — the exact authorization data that the child trust accepted unchanged. That stripping is what makes the Trentham edge a **real, separate** security boundary where the parent↔child trust is not: the same injected SID that the root accepted (step 4) is removed at the forest edge (steps 5 and 7). The edge is "mostly" a boundary, not fully, for one reason: it still honours a **real, native Aldermont group that was legitimately granted access** (step 6). The filter stops forgery; it cannot stop a permission you actually gave and forgot. **So the forest is close to a true boundary — provided your cross-forest grants are clean.**

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
- **Boundary B — the acquired trust. The one protection to re-enable, named exactly.** During the acquisition the forest trust's SID-history filtering was **turned off** so migrated accounts would keep working, and it was never turned back on. Re-enable it to its correct default. On a domain controller in `aldermont.local`, for trust B only:
  ```
  netdom trust aldermont.local /domain:trentham.local /enablesidhistory:no
  netdom trust aldermont.local /domain:trentham.local /quarantine:yes      # confirm SID filtering enforced
  netdom trust aldermont.local /domain:trentham.local /enablesidhistory    # verify -> "SID history ... No"
  ```
  **Exact scope:** this changes only what Trentham will accept from the **Aldermont** forest across trust B; it does not touch trust A, the intra-forest behaviour, or any other trust. Default is `No`, and `No` is correct; the migration left it `Yes`.
- **Close the actual door (the leftover grant).** Re-enabling filtering does not remove a *native* grant, so also **remove `LegacyAcq`'s rights on the Trentham `crown` resource** and delete the stale membership path, then inventory every other Aldermont group or foreign security principal holding rights inside Trentham.
- **Stricter posture — selective authentication, named exactly, and what it costs Trentham.** For defence in depth, Trentham (the resource side of trust B) sets the incoming trust from Aldermont to **selective authentication**, so an Aldermont principal reaches a Trentham resource *only* where Trentham has explicitly granted it. On a `trentham.local` DC:
  ```
  netdom trust trentham.local /domain:aldermont.local /SelectiveAuth:yes
  ```
  then, per Trentham resource that Aldermont legitimately needs, grant the Aldermont principal the **"Allowed to authenticate"** right on that computer object (its ACL), e.g. on `TRENTHAM-DC` for the `crown` share only. **Cost to Trentham:** every legitimate cross-forest access must then be granted per-resource; anything relying on today's blanket forest-wide access breaks until re-permitted, and Trentham's admins own the ongoing overhead of that allow-list. Correct trade, but an operational commitment, not a checkbox. This is specific to **path B (the Trentham crossings)** and touches neither trust A nor the intra-forest paths.
- **The migration artefact (account history) — specific to the step-7 path.** Account history should have been **cleared once the migration completed years ago** — it is transitional, not permanent. For our own exercise this is already done: the `sIDHistory` we wrote in step 7 was reverted and read back empty (Closeout, Write path 2). For the *estate*, sweep **both** directories for stray `sIDHistory` values and remove any found, and turn on the **4765/4766** auditing above so the next one is caught the day it is written.

---

## 5. The wider surface — what Aldermont should assess next

We exercised the trust paths our scope covered. The following are *additional* trust-abuse avenues we did **not** test and that Aldermont should have assessed — listed as gaps in your assurance, not as a to-do list of attacks:

- **Delegation reachable across a trust.** Kerberos delegation (unconstrained, constrained, resource-based) that spans a trust can turn a foothold on one side into authentication on the other. *(The estate contained a deliberate unconstrained-delegation decoy; real delegation across your trusts deserves a proper review.)*
- **Coercion across a trust.** Techniques that *force* a server or DC to authenticate to an attacker (printer/EFS-style coercion) can pull privileged authentication across a trust boundary. Assess which of your machines can be coerced and where that authentication can land.
- **Group memberships held by foreign principals.** `LegacyAcq` was one forgotten grant; a full inventory of **every** cross-forest and foreign-security-principal membership in both directories is the single highest-value hygiene task to come out of this report.
- **The forest-to-cloud boundary.** The most important trust edge most organisations now own is the one between Active Directory and a **cloud identity provider** (Entra ID / federation / directory sync). Compromise of the on-premises forest very often extends to the cloud tenant through that connector. This is where this class of attack is heading, and it should be in scope for your next assessment.

---

## 6. Closeout — every object we wrote, and the read-back proving it is gone

We committed to minimal, reversible changes and to proving removal with an **independent read-back** for each write path. There were **exactly two** directory writes — one in `aldermont.local`, one in `corp.aldermont.local` — both reverted and both evidenced below; **no** object was written in `trentham.local` (we authenticated in and read a single file, nothing more). The complete per-directory inventory:

| Directory / forest | Object · attribute written | Status |
|--------------------|----------------------------|--------|
| `aldermont.local` (root) | `CN=LegacyAcq` · `member` | performed → **reverted** (read-back below) |
| `corp.aldermont.local` (child) | `CN=svc.backup` · `sIDHistory` | performed → **reverted** (read-back below) |
| `trentham.local` (acquired) | **none** — read-only (`\\TRENTHAM-DC\crown\crownjewel.txt`) | no write |

### Write path 1 — group membership (performed, then reverted)

| Field | Value |
|-------|-------|
| Directory / forest | `aldermont.local` |
| Object (full DN) | `CN=LegacyAcq,CN=Users,DC=aldermont,DC=local` |
| Attribute changed | `member` |
| Original value (captured before any change) | **empty** (no members) |
| New value (during step 6) | `+ CN=r.bello,CN=Users,DC=corp,DC=aldermont,DC=local` |
| Purpose / time | open the Trentham door for the cross-forest read; reverted same session |

**Read-back evidence (independent query each time, not a cached result):**
```
# BEFORE  (member attribute empty)
nxc ldap 192.168.60.10 -u r.bello -p *** --query '(sAMAccountName=LegacyAcq)' 'member'
  [+] Response for object: CN=LegacyAcq,CN=Users,DC=aldermont,DC=local      (no member line)

# AFTER ADD  (one member present)
  member: CN=r.bello,CN=Users,DC=corp,DC=aldermont,DC=local

# AFTER REVERT  (removed; attribute empty again = original state restored)
nxc ldap 192.168.60.10 -u r.bello -p *** --query '(sAMAccountName=LegacyAcq)' 'member'
  [+] Response for object: CN=LegacyAcq,CN=Users,DC=aldermont,DC=local      (no member line)
```
The `member` attribute returned to its exact pre-change value (empty) — the change is fully removed.

### Write path 2 — account history (`sIDHistory`), performed then reverted

To demonstrate durable intra-forest access via the account-history mechanism (step 7) — and to prove it is fully reversible — we injected the child's **CORP `Domain Admins`** SID into the `sIDHistory` of the seeded normal child account `svc.backup`, confirmed the injected authority is **honoured intra-forest** (no SID filtering inside the forest) and is **stripped at the Trentham edge** (contrast with step 5), then removed it and read back the original (empty) value.

| Field | Value |
|-------|-------|
| Directory / forest | `corp.aldermont.local` (child) |
| Object (full DN) | `CN=svc.backup,CN=Users,DC=corp,DC=aldermont,DC=local` |
| Attribute changed | `sIDHistory` |
| Original value (captured before any change) | **empty** (no value) |
| New value (during step 7) | `+ S-1-5-21-566709512-1948993727-1589621289-512` (CORP `Domain Admins`) |
| Technique | `mimikatz sid::add /sam:svc.backup /new:<CORP Domain Admins SID>` (intra-forest) |
| Event generated | **4765** — "SID History was added to an account" (on ALDER-CHILD-DC) |
| Purpose / time | demonstrate durable intra-forest account-history access; reverted same session |

**Read-back evidence (independent query each time, not a cached result):**
```
# BEFORE  (sIDHistory empty)
nxc ldap 192.168.60.11 -u r.bello -p *** --query '(sAMAccountName=svc.backup)' 'sIDHistory'
  [+] Response for object: CN=svc.backup,CN=Users,DC=corp,...     (no sIDHistory line)

# AFTER ADD  (injected CORP Domain Admins SID present; Event 4765 logged)
  sIDHistory: S-1-5-21-566709512-1948993727-1589621289-512

# AFTER REVERT  (cleared; attribute empty again = original state restored)
nxc ldap 192.168.60.11 -u r.bello -p *** --query '(sAMAccountName=svc.backup)' 'sIDHistory'
  [+] Response for object: CN=svc.backup,CN=Users,DC=corp,...     (no sIDHistory line)
```
The `sIDHistory` attribute returned to its exact pre-change value (empty) — the migration artefact we introduced to prove the path is fully removed. (The lab's own `99-reset-lab.ps1` strips injected `sIDHistory` as well, so nothing of ours persists either way.)

### Everything else
- **No accounts** were created or modified; **no group** other than `LegacyAcq` was touched; **no ACL** was changed.
- **No `krbtgt` or other secret was altered.** The key material was *read* (replication) to forge tickets; nothing was written back.
- **No tickets or tools left on estate hosts.** Forged tickets lived only on the testing host and are disposable.

**Net state:** both directories are byte-for-byte in their pre-engagement configuration on every object we touched. The one standing risk we did **not** create but recommend Aldermont remove is the pre-existing `LegacyAcq → crown` grant (Section 4).

---

*Supporting evidence (ticket/PAC captures, the filter diagnosis, the cross-forest read, and the raw before/after read-backs quoted above) is retained in the engagement `evidence/` directory and available on request.*
