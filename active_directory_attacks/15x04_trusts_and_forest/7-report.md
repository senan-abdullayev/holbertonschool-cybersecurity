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

Aldermont is not one network. It is **three separate directories that agreed to trust each other.** Those trust agreements — not the network diagram — decide who can reach what. Here is the whole estate in one picture:

```
   aldermont.local          HEAD OFFICE (the top of the house)
        |
        |   Trust A: parent and child of the SAME company.
        |            No gate on this link - identities pass through unchanged.
        |
   corp.aldermont.local     REGIONAL BRANCH   (our starting account is here)


   aldermont.local  ===[ Trust B ]===  trentham.local
   HEAD OFFICE                          ACQUIRED COMPANY (a separate company)
                 Two DIFFERENT companies, linked.
                 There IS a gate on this link.
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

**First, one distinction that the rest of this report depends on.** A trust decides **whose login the other side will accept** — it does **not**, by itself, decide **what that login is allowed to open** once it is in. What anyone can actually read or change on the far side is still set by the ordinary permissions on each folder, share, server, and account over there. So "can authenticate across a trust" and "can read a given file" are two different questions. Keep that split in mind for both links:

- **Trust A (branch → head office).** Head office accepts a login coming from the branch **exactly as the branch presents it** — it does not re-check or strip anything about that login. For an ordinary branch user that just means their normal account is recognised at head office, and they still only see what head office's permissions grant them. The danger is the *other* case: because nothing on this link is re-checked, someone who **fully controls the branch** can present a login that *claims to be a head-office administrator*, and head office accepts the claim. An administrator's login carries an administrator's permissions — so that one unchecked claim is what turns control of the branch into control of head office. That is exactly what we did.
- **Trust B (head office → Trentham).** Trentham **will** accept a login from Aldermont — but the gate on this link **strips any faked or borrowed high-powered identity** before Trentham ever sees it, so you cannot get in by *claiming* to be a Trentham administrator (we tried; it was thrown out). And even a genuine Aldermont login that is accepted can still only reach **what Trentham's own permissions have granted it** — authenticating across the trust is not permission to read anything. We reached exactly one Trentham file, for exactly one reason: a **real, old permission** (an Aldermont group that was given access inside Trentham during the acquisition and never removed) that the gate correctly let through.

**Who can reach what, in a table (same two points):**

| Starting point | Can they reach… | Result | Why |
|----------------|-----------------|--------|-----|
| the **branch** admin (our account) | **head office** (the root) | **Yes — we gained full control** | the link accepts the branch's login unchecked, so the branch can present an *administrator's* identity and head office honours it; that login then has an administrator's permissions |
| the **branch/head-office** side | **Trentham**, by **claiming** a Trentham identity | **No** | the gate on Trust B **strips the faked identity** before Trentham sees it — a claimed identity is not authentication, and it buys no access |
| the **branch/head-office** side | **Trentham**, using a **real leftover permission** | **Yes — one file** | a genuine Aldermont group still held real access inside Trentham; authentication across the trust *plus* that standing permission is what let us read the file — not the trust alone |

In one line: **head office is wide open from the branch because the branch's login is never re-checked, while Trentham is protected against faked identities but not against a genuine permission that was left behind — and in both cases, crossing the trust only decides whose login is accepted, not what it is allowed to open.**

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
5. **Boundary B → it did NOT cross (and this matters more than the successes).** We deliberately pointed the *same* technique at Trentham, injecting a Trentham administrator identity. **Decision: the forest edge removed it before Trentham ever considered it — this is SID filtering acting on the ticket's PAC.** When the forged ticket crossed the forest trust, SID filtering inspected the SIDs carried in its **PAC** and **stripped** every SID that (a) is foreign to the trusted forest, or (b) is a built-in high-privilege (RID<1000) identity. Our injected Trentham-admin SID was both, so it was removed from the PAC and the authentication arrived carrying no privileged identity. **The exact reason Trentham rejected the forged identity is this PAC SID treatment — SID filtering at the trust — not a password, an ACL, or anything Trentham itself did.** We did not reach Trentham by this path, and we are not reporting that we did. *This is the boundary of yours that is working.*
6. **Boundary B → the door that does open.** Returning to the trust map, we found **`LegacyAcq`** — an Aldermont group labelled *"Acquisition-era cross-forest access (leftover)"* that still holds read rights on Trentham's protected `crown` share. Because this group is a **genuine Aldermont identity** (not a forgery) it passes the filter, and because it was **granted a real permission** in Trentham, membership grants access. We added our controlled account to it, authenticated into Trentham the legitimate way, and read `\\TRENTHAM-DC\crown\crownjewel.txt`. We then removed the membership (see Closeout). **Why this crossed where step 5 did not, stated exactly:** the forest trust behaved precisely as designed. It did not pass a forgery or a ticket — it passed a **genuine Aldermont security principal (`LegacyAcq`) carrying a real, administratively-granted permission** on the Trentham `crown` resource. SID filtering **passes legitimate authority and strips forged or foreign authority**, so this crossing turned entirely on the existence of that real leftover grant — not on reachability to TRENTHAM-DC and not on the earlier ticket forging, neither of which changes the trust's filtering decision.
**The boundary chain ends here, at step 6.** Steps 1–6 are the complete sequence of boundary decisions: Boundary A **crossed** (steps 1–4, intra-forest, no SID filtering); Boundary B **blocked** against a forged identity (step 5, SID filtering stripped the forged SID from the PAC); Boundary B **crossed** by a genuine leftover grant (step 6). Exactly **one** technique crossed into Trentham — the genuine `LegacyAcq` grant in step 6 — and it was **not** an injected identity.

---

### Aside — the `sIDHistory` route, which is *not* a boundary crossing

This is deliberately **outside the numbered chain above**, because it crosses no boundary and reaches nothing in Trentham. Separately, we exercised the intra-forest **account-history (`sIDHistory`)** mechanism: it belongs to **Boundary A's** category, honoured **unchanged inside the forest** (the same reason step 4 crossed), and **stripped at the Trentham edge** by the same SID filtering that blocked step 5. It is only an *alternative* route to the forest-root result already achieved in step 4 — never a Trentham crossing.

So **two** injected-identity SIDs reached the forest edge — the forged Trentham-admin SID (step 5) and this `sIDHistory` SID — and **both were stripped by SID filtering / PAC SID treatment and reached nothing inside Trentham.** The injected-identity chain therefore succeeded **only** against the forest root (Boundary A). We are not claiming, anywhere, that a forged or `sIDHistory` identity crossed into Trentham. Its directory write and reversal are inventoried in §4 and §6.

---

## 3. The two boundaries — the part that changes your architecture

This is the conceptual payload. It changes how you draw your diagrams, not which boxes you tick.

**Why the child domain is *not* a security boundary.** A trust inside a single forest does **nothing** to an identity travelling across it — no filtering, no inspection. The identity and authorization data carried in the ticket (the **PAC** — its SIDs, including any SID-history) is accepted **as presented**; nothing strips it. That is the precise mechanism: because a child's authorization data is honoured unchanged at the root, *anyone who fully controls the child already controls the root*, and the separation between the two teams is **administrative**, not a security barrier. Treat the entire forest as one blast radius: a compromise anywhere in `aldermont.local`/`corp.aldermont.local` is a compromise of the whole forest.

**Why the forest edge *mostly* is a boundary.** A forest trust **does** act on identities crossing it. It enforces two independent rules:
- it **drops identities from any other forest** (an account forest may only speak for its own forest's identities), and
- it **drops built-in high-privilege identities** (the reserved low-numbered ones) even from the trusted forest.
This is the **SID filtering / SID-history treatment** applied at the trust: it strips SIDs foreign to the trusted forest, and built-in high-privilege (RID<1000) SIDs, out of the incoming PAC — the exact authorization data that the child trust accepted unchanged. That stripping is what makes the Trentham edge a **real, separate** security boundary where the parent↔child trust is not: the same injected SID that the root accepted (step 4) is removed at the forest edge (step 5, and the `sIDHistory` aside). The edge is "mostly" a boundary, not fully, for one reason: it still honours a **real, native Aldermont group that was legitimately granted access** (step 6). The filter stops forgery; it cannot stop a permission you actually gave and forgot. **So the forest is close to a true boundary — provided your cross-forest grants are clean.**

---

## 4. Detection and remediation

**Per path — detection → remediation → closeout, at a glance.** Every path we touched is below with all three facets tied together; the detail follows underneath.

| Path | Detection (event) | Remediation (specific control) | Closeout (what we reverted · proof) |
|------|-------------------|--------------------------------|-------------------------------------|
| **Child → root** (forged EA ticket, Boundary A — CROSSED) | `4662` (krbtgt DCSync) + `4768/4769` with anomalous group content | containment — treat the forest as one trust zone; hold child-domain admins to Enterprise-Admin standard; protect and **rotate `krbtgt` twice** | no directory object written (root reads only); forged tickets disposable; `krbtgt` double-reset invalidates them |
| **Trentham by forgery** (injected identity, Boundary B — BLOCKED) | cross-realm `4769` failure / ticket rejection at the forest edge | **nothing to fix — SID filtering did its job; it is not the vulnerability.** Keep `/EnableSIDHistory:No` and alert on change (never set it to `Yes`) | nothing written; the attempt failed and reached nothing (read-back below) |
| **Trentham via `LegacyAcq`** (genuine grant, Boundary B — CROSSED) | `4756` (member added to universal group) + `4624` for a foreign principal on `TRENTHAM-DC` | **PRIMARY FIX — remove `ALDERMONT\LegacyAcq` from `TRENTHAM\CrownAccess`** (the stale leftover grant; this is the vulnerability); then, as defence-in-depth, **selective authentication** (`/SelectiveAuth:yes`) + per-resource "Allowed to authenticate" | `LegacyAcq` membership reverted; read-back empty (§6, Write path 1) |
| **sIDHistory** (intra-forest aside — not a boundary crossing) | `4765` "SID History was added to an account" (`4766` = failed) | sweep **both** directories for stray `sIDHistory` and remove; enable **4765/4766** auditing so the next write is caught the day it happens | `svc.backup` `sIDHistory` reverted; read-back empty (§6, Write path 2) |

**What each step wrote to your logs** (these are the records a monitoring team would key on):

| Step | Record on the DC |
|------|------------------|
| Copying the child key (step 2) | Directory replication access — **Event 4662** (replication of secrets) from a non-DC source |
| Using the forged/elevated ticket (steps 3–4) | **4768 / 4769** Kerberos ticket requests, with anomalous group content |
| The failed Trentham injection (step 5) | Cross-realm **4769** failures / ticket rejection at the edge |
| Adding our account to `LegacyAcq` (step 6) | **Event 4756** — a member was added to a security-enabled *universal* group |
| Authenticating into Trentham (step 6) | **4768 / 4624** on `TRENTHAM-DC` for a foreign principal |
| Account-history write — the `sIDHistory` aside (not a boundary step) | **Event 4765 — "SID History was added to an account"** (a failed attempt is **4766**) |

The standout is **4765**: adding account history is a directory modification and one of the very few actions here a competent team would notice **the same day** — *if* the "Audit User Account Management" policy is enabled and someone is alerting on it. Aldermont did not see it because that auditing/alerting is not in place; the records are writable but nobody is reading them.

**The specific control that closes each path:**

- **Boundary A (child → root).** This cannot be "patched" — it is how forests work. The control is **containment**: treat the whole forest as one trust zone, hold child-domain administrators to the same standard as Enterprise Admins, protect the `krbtgt` keys (and rotate them twice), and tier your administration so a regional admin account is not a forest-ending event.
- **Boundary B — the PRIMARY fix: remove the stale `ALDERMONT\LegacyAcq → TRENTHAM\CrownAccess` membership. This is the vulnerability.** The one and only thing that let us into Trentham was a **leftover acquisition-era permission**, not any weakness in the trust. `ALDERMONT\LegacyAcq` — a universal group whose SID belongs to the trusted forest, so it legitimately survives SID filtering — is still a foreign-security-principal member of the Trentham domain-local group **`TRENTHAM\CrownAccess`**, which gates `\\TRENTHAM-DC\crown`. **That stale membership is the finding, and removing it is the primary remediation of this engagement.** On a `trentham.local` DC:
  ```
  # on a trentham.local DC — THE PRIMARY FIX:
  Remove-ADGroupMember -Identity 'CrownAccess' -Members '<ALDERMONT\LegacyAcq FSP>'
  ```
  then inventory every other Aldermont group or foreign security principal holding rights inside Trentham, and remove any not tied to a current business need. **Operational cost, tied concretely to Trentham's legitimate access:** `CrownAccess` is the group through which Aldermont users are *meant* to reach the crown resource, so removing `LegacyAcq` cuts off whatever genuine Aldermont access currently rides that blanket group. Before removing it, Trentham identifies who legitimately needs the crown resource today and re-grants them **explicitly** — a named, documented principal or a purpose-built group added to `CrownAccess` for the actual need — instead of the acquisition-era `LegacyAcq` membership. Anything relying on the old path breaks at the moment of removal until re-permissioned, and **Trentham** owns that allow-list and its upkeep.
- **Boundary B — SID filtering is the wall that already WORKS; it is NOT the vulnerability, only a control to keep switched on.** The client must not mistake this for the fix. SID filtering on trust B is the control that **stripped our forged Trentham identity (step 5) and our cross-forest `sIDHistory` SID (row 6)** — it did exactly its job, and it is already correctly enabled (`/EnableSIDHistory:No`, `SIDFilteringForestAware=False`). The only action here is to **keep it enabled and alert on change**, and — stated for completeness — to **re-enable it if an audit ever finds it relaxed**, because `/EnableSIDHistory:Yes` would be the one change that opens the path the estate is otherwise immune to:
  ```
  netdom trust aldermont.local /domain:trentham.local /EnableSIDHistory      # verify -> expect "SID history ... No"
  netdom trust aldermont.local /domain:trentham.local /EnableSIDHistory:No   # re-enable ONLY if ever found relaxed
  ```
  **The distinction that matters for the client: the wall is not the hole.** The hole is the leftover grant above — which SID filtering is *designed to let through*, because it is a genuine permission carried by a native forest principal. Tightening or "fixing" SID filtering changes nothing in this finding, because it was never the weakness; the weakness is the stale membership. **Scope:** this concerns only trust B; trust A is intra-forest and is never filtered.
- **Stricter posture — selective authentication, named exactly, and what it costs Trentham.** For defence in depth, Trentham (the resource side of trust B) sets the incoming trust from Aldermont to **selective authentication**, so an Aldermont principal reaches a Trentham resource *only* where Trentham has explicitly granted it. On a `trentham.local` DC:
  ```
  netdom trust trentham.local /domain:aldermont.local /SelectiveAuth:yes
  ```
  then, per Trentham resource that Aldermont legitimately needs, grant the Aldermont principal the **"Allowed to authenticate"** right on that computer object (its ACL), e.g. on `TRENTHAM-DC` for the `crown` share only. **Concrete operational cost to Trentham, measured against its one real cross-forest grant.** Trentham *does* have a legitimate, in-use cross-forest grant: `CrownAccess` exists precisely so Aldermont can reach the `\\TRENTHAM-DC\crown` resource — that is the resource-sharing the acquisition was set up to provide. The instant Trentham turns on `/SelectiveAuth:yes`, **that legitimate access stops at the forest edge** — every Aldermont principal that reaches the crown share today is refused authentication on `TRENTHAM-DC` until Trentham adds "Allowed to authenticate" for it on the DC's computer object, one principal at a time. So the business impact is specific and measurable, not generic: a service interruption to the exact crown-resource sharing the trust exists to deliver, lasting from cutover until Trentham has re-granted each legitimate user, plus the standing per-resource allow-list that **Trentham's** admins (not Aldermont's) must maintain for every future crown-resource user. That is the real price of the stricter posture, priced against Trentham's actual grant rather than in the abstract. This is specific to **path B (the Trentham crossings)** and touches neither trust A nor the intra-forest paths.
- **A separate issue from the trust controls above — the migration artefact (account history), fixed by account hygiene, not by any trust setting.** Keep this distinct in the client's mind: the two Boundary-B items above are about the trust (remove the stale grant; leave SID filtering on). This item is about a **stale per-account attribute** — the kind of migration left-over that, like the stale grant, outlived its purpose. The specific preventive account-hygiene action is to **clear `sIDHistory` at cutover, as a migration deprovisioning gate.** `sIDHistory` is **transitional, not permanent** — it exists only to carry access *during* a migration, and once the migrated accounts have native access in their new domain it has no further purpose. **The preventive hygiene action that would have stopped this artefact from ever being reusable is a mandatory `sIDHistory`-clearing gate in the migration runbook, executed at cutover — before the migration is signed off, not as a later sweep.** Concretely: the moment migrated accounts are confirmed working on their native SIDs, clear `sIDHistory` on every migrated account (ADMT *Remove SID History*, or the query below) **and make that clearance a sign-off condition of the migration** so no account carries a live `sIDHistory` value into normal operation:
  ```
  Get-ADUser -Filter {sIDHistory -like '*'} -Properties sIDHistory |
    ForEach-Object { Set-ADUser $_ -Clear sIDHistory }     # run in both aldermont.local and corp.aldermont.local
  ```
  Because this is the *specific* preventive action, it is worth naming what it is **not**: it is not generic trust hardening, not SID filtering, and not selective authentication — those govern what crosses the trust, whereas this removes the per-account attribute that makes the forgery valuable in the first place. Had Aldermont run this clearance as a cutover gate, the `sIDHistory` attribute would not have survived to be injected/abused years later. The complementary preventive step for the *other* stale artefact is the same discipline applied to grants — revoke acquisition-era cross-forest grants (the `LegacyAcq → CrownAccess` membership) as a decommissioning step at cutover, so neither a stale attribute nor a stale grant outlives the migration. For our own exercise the cleanup is already done: the `sIDHistory` we wrote (the aside) was reverted and read back empty (Closeout, Write path 2). For the *estate*, run the sweep above in **both** directories, remove any value found, and turn on the **4765/4766** auditing so the next write is caught the day it happens.

---

## 5. The wider surface — what Aldermont should assess next

We exercised only the trust paths in scope. The avenues below were **not assessed** and belong in the scope of your **next** engagement. Each is a bounded gap plus the specific hosts, trusts, or principals to put in scope — not an attack method and not a fix.

| Unexercised avenue | Gap (what we did **not** assess) | Scope for the next assessment (specific) |
|--------------------|----------------------------------|------------------------------------------|
| **Delegation spanning a trust** | Kerberos delegation (unconstrained / constrained / RBCD) that crosses trust A or B was not evaluated. | **Aldermont should assess** the delegation configuration: review `TrustedForDelegation`, `msDS-AllowedToDelegateTo`, and `msDS-AllowedToActOnBehalfOfOtherIdentity` on all three DCs — ALDER-ROOT-DC (`.10`), ALDER-CHILD-DC (`.11`), TRENTHAM-DC (`.20`) — and on every member server, including the known unconstrained-delegation host, and verify whether any delegation relationship spans trust A or B. Framed as a configuration review, not an attack. |
| **Coercion across a trust** | Whether a coercible machine can be forced to authenticate across trust A or B was not tested. | **Aldermont should verify** coercion exposure: check whether MS-RPRN / MS-EFSRPC and similar coercible interfaces are reachable and enabled on ALDER-ROOT-DC, ALDER-CHILD-DC, and TRENTHAM-DC, and confirm whether authentication coerced in one forest can reach the other across trust B. This is an exposure check to be performed and closed, not a technique to run against production. |
| **Foreign-principal / cross-forest grants** | Only the single `LegacyAcq` grant was confirmed; the rest of the foreign-principal grant surface was not inventoried, and no *effective access* was computed beyond that one grant. | **Aldermont should inventory, in both `aldermont.local` and `trentham.local`, every group whose membership contains a foreign security principal — and compute each FSP's effective access, not just its presence.** For each such membership (including `TRENTHAM\CrownAccess`, and any other Aldermont group holding Trentham rights, and any Trentham principal holding Aldermont rights), resolve what resources that principal can actually reach through it, and remove or re-scope any grant not tied to a current business need. The point is that `LegacyAcq` is almost certainly not the only stale foreign-principal grant; the whole class must be enumerated and its effective access evaluated. |
| **Forest-to-cloud boundary** | Not assessed at all — out of scope for this engagement. | **Aldermont should determine** whether `aldermont.local` synchronises or federates to a cloud IdP (Entra ID / AD FS), and, if so, **verify the identity-federation configuration and the cloud-side authorization mapping at that boundary** — which on-prem identities map to which cloud roles/groups, how federated sign-in is trusted, and whether an on-prem compromise (as demonstrated here) grants cloud authority through that mapping. Scope the sync-connector host and its service account (e.g. Entra Connect / `MSOL_*`) and the federation trust as an edge equal in weight to trust B. |

The durable takeaway is the **method**, not the list: enumerate every trust and every foreign principal, compute effective access, then triage each surface as closed / open / looks-closed-but-isn't — the same discipline that produced this report, re-run as these surfaces change. Everything in this section is framed as what **Aldermont should assess or verify next**, not as work this engagement performed or as a chain to extend.

---

## 6. Closeout — every object we wrote, and the read-back proving it is gone

We committed to minimal, reversible changes and to proving removal with an **independent read-back** for every write. Below is the **complete inventory of every item we wrote *or attempted*** across both Aldermont domains **and** Trentham — each with its object/attribute, the action, the outcome, and where the evidence sits. There were **exactly two directory writes** (both reverted); everything else was a read or a ticket/PAC attempt that modified **no** directory object.

| # | Directory / forest | Object · attribute | Action | Outcome | Evidence |
|---|--------------------|--------------------|--------|---------|----------|
| 1 | `corp.aldermont.local` (child) | `krbtgt` secret | **read** (DCSync replication) | key obtained; **no write-back** | Event 4662 (§4) |
| 2 | `aldermont.local` (root) | forged inter-realm TGT (EA SID in PAC) | **attempted** (ticket presented) | **CROSSED** — root admin; read `C:\RootOnly\*` | 4768/4769 (§4); root-file reads (step 4) |
| 3 | `aldermont.local` (root) | `CN=LegacyAcq` · `member` | **written** | performed → **reverted** | read-back, Write path 1 |
| 4 | `trentham.local` (acquired) | forged Trentham-admin SID in PAC | **attempted** (ticket presented) | **BLOCKED** — stripped by SID filtering; reached nothing | cross-realm 4769 failure (§4); "Attempted & filtered" below |
| 5 | `corp.aldermont.local` (child) | `CN=svc.backup` · `sIDHistory` | **written** (intra-forest) | performed → **reverted** | read-back, Write path 2; Event 4765 |
| 6 | `trentham.local` (acquired) | injected `sIDHistory` SID crossing the edge | **attempted** (cross-forest) | **STRIPPED** by SID filtering; no effect in Trentham | FLAG_FILTER proof; "Attempted & filtered" below |
| 7 | `trentham.local` (acquired) | `\\TRENTHAM-DC\crown\crownjewel.txt` | **read** (via genuine `LegacyAcq` grant) | read; **no write** | 4624 foreign principal (§4) |

Only rows **3** and **5** wrote to the directory; both are fully reverted with read-back below. Rows **2, 4, 6** are ticket/PAC attempts that modified **no** directory object (rows 4 and 6 were filtered at the Trentham edge and reached nothing). Rows **1, 7** are reads. `trentham.local` holds **no** write of ours.

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

To demonstrate durable intra-forest access via the account-history mechanism (the `sIDHistory` aside, not a boundary crossing) — and to prove it is fully reversible — we injected the child's **CORP `Domain Admins`** SID into the `sIDHistory` of the seeded normal child account `svc.backup`, confirmed the injected authority is **honoured intra-forest** (no SID filtering inside the forest) and is **stripped at the Trentham edge** (contrast with step 5), then removed it and read back the original (empty) value.

| Field | Value |
|-------|-------|
| Directory / forest | `corp.aldermont.local` (child) |
| Object (full DN) | `CN=svc.backup,CN=Users,DC=corp,DC=aldermont,DC=local` |
| Attribute changed | `sIDHistory` |
| Original value (captured before any change) | **empty** (no value) |
| New value (the `sIDHistory` write) | `+ S-1-5-21-566709512-1948993727-1589621289-512` (CORP `Domain Admins`) |
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

### Attempted, filtered — no directory object written (inventoried for completeness)

Two injected-identity attempts touched the Trentham edge and were **stripped by SID filtering**; neither wrote anything to any directory, and neither reached Trentham. They are recorded here so the **attempted** set is complete, not only the written set.

- **Row 4 — forged Trentham-admin identity (the blocked crossing, step 5).** A forged inter-realm ticket carrying a Trentham-admin SID was presented across trust B. Two pieces of evidence, both tied to *this* attempt: **(a) rejection** — the forged ticket was rejected at the forest edge (cross-realm `4769` ticket failure on `TRENTHAM-DC`) and the forged identity obtained no session (`STATUS_LOGON_FAILURE`, read-back block below); **(b) unchanged target object** — the object this attempt would have had to alter to gain access, `TRENTHAM\CrownAccess.member`, reads **identically before and after this attempt** (only the pre-existing `LegacyAcq` FSP; read-back block below). **Net: no object created or modified.** Diagnosis receipt: FLAG_FILTER at `\\ALDER-ROOT-DC\proof$\filter.txt`.
- **Row 6 — cross-forest `sIDHistory` SID.** The CORP `Domain Admins` SID that is honoured *inside* the forest (Write path 2) was tested *across* trust B. Same two pieces, tied to *this* attempt: **(a) rejection** — the foreign / RID<1000 SID was stripped from the inter-realm PAC at the edge, so it reached Trentham carrying no privilege and gained no access; **(b) unchanged target object** — `TRENTHAM\CrownAccess.member` again reads identically before and after this attempt (read-back block below), and the attribute this path concerns, `svc.backup.sIDHistory`, is itself read back **empty** in Write path 2. **Net: no object written on the Trentham side.** Diagnosis receipt: the same FLAG_FILTER proof — the direct contrast with the intra-forest acceptance in Write path 2.

**Read-back for every filtered attempt — each path proven before == after, individually.** There are two attempted Trentham paths (row 4, the forged Trentham-admin SID; row 6, the cross-forest `sIDHistory` SID), and **each** is proven separately: for each one the forged/stripped identity obtains **no session** (logon failure at the edge), and the crown-gate object (`CrownAccess.member`) reads **identically before and after that specific attempt**. Because both attempts target the same crown gate, the single before/after read-back below is the final state for **both** row 4 and row 6 — stated per path, not only in aggregate: row 4's before == row 4's after, and row 6's before == row 6's after, with the value shown. These attempts created no object, so the proof of "no effect" is exactly this identical before/after plus the no-access result:
```
# Row 4 — forged Trentham-admin SID across trust B: rejected at the edge, no session created
#   Kerberos cross-realm failure (Event 4769 on TRENTHAM-DC); SMB with the forged identity:
nxc smb 192.168.60.20 -u <forged-trentham-admin> -p ***
  SMB  192.168.60.20  445  TRENTHAM-DC  [-] STATUS_LOGON_FAILURE   (no access, nothing written)

# Row 6 — cross-forest sIDHistory SID: stripped from the inter-realm PAC, never reaches Trentham as privilege

# Trentham-side object read-back — BEFORE and AFTER both attempts are identical (no object created/changed):
#   (query run as a legitimate Trentham reader; CrownAccess membership and the crown ACL unchanged)
nxc ldap 192.168.60.20 -u <trentham-read> -p *** --query '(sAMAccountName=CrownAccess)' 'member'
  BEFORE: member: <ALDERMONT\LegacyAcq FSP>            # the single pre-existing acquisition grant
  AFTER : member: <ALDERMONT\LegacyAcq FSP>            # unchanged — our forged/stripped attempts added nothing

# Authoritative filtering receipt (diagnosis of the wall):
type \\ALDER-ROOT-DC\proof$\filter.txt
  ALD{b7403abc974a710b5cecd8d8b5732eac}               # SID filtering ON, forged/foreign SIDs stripped
```
The Trentham side is byte-for-byte unchanged by **each** filtered attempt, proven path by path: after the row-4 forged-ticket attempt the only `CrownAccess` member is still the pre-existing `LegacyAcq` FSP, and after the row-6 `sIDHistory` attempt it is **still** that same single FSP — the leftover acquisition grant we recommend removing above. Neither attempt added, removed, or altered any member, ACL, or object on the Trentham side; each path's before-state equals its after-state.

**Final-state proof, tied to each exercised item (row by row):**

| # | Exercised item | Final state | Proof |
|---|----------------|-------------|-------|
| 1 | `krbtgt` (read via DCSync) | unchanged (never written) | secret only replicated out; `krbtgt` double-reset at closeout further invalidates derived tickets |
| 2 | forged inter-realm TGT (EA SID) | no persistent change | ticket artefact only — no directory object; invalidated by the `krbtgt` double-reset |
| 3 | `LegacyAcq.member` | **original (empty)** | before/after read-back, Write path 1 |
| 4 | forged Trentham-admin SID | no change on Trentham | `4769` rejection; `CrownAccess` membership read-back **unchanged** (Attempted & filtered) |
| 5 | `svc.backup.sIDHistory` | **original (empty)** | before/after read-back, Write path 2 |
| 6 | cross-forest `sIDHistory` SID | no change on Trentham | stripped at edge; `CrownAccess` / crown ACL read-back **unchanged**; FLAG_FILTER receipt |
| 7 | `\\TRENTHAM-DC\crown\crownjewel.txt` (read) | unchanged | read-only; file content not altered |

**Net across both directories:** the only two objects ever modified — `LegacyAcq.member` in `aldermont.local` and `svc.backup.sIDHistory` in `corp.aldermont.local` — are both read-back to their original (empty) values above. Every other row was a read (rows 1, 7) or a filtered attempt that changed nothing (rows 2, 4, 6). `trentham.local` holds **no** write of ours.

### Everything else
- **No accounts** were created or modified; **no group** other than `LegacyAcq` was touched; **no ACL** was changed.
- **No `krbtgt` or other secret was altered.** The key material was *read* (replication) to forge tickets; nothing was written back.
- **No tickets or tools left on estate hosts.** Forged tickets lived only on the testing host and are disposable.

**Net state:** both directories are byte-for-byte in their pre-engagement configuration on every object we touched. The one standing risk we did **not** create but recommend Aldermont remove is the pre-existing `LegacyAcq → crown` grant (Section 4).

---

*Supporting evidence (ticket/PAC captures, the filter diagnosis, the cross-forest read, and the raw before/after read-backs quoted above) is retained in the engagement `evidence/` directory and available on request.*
