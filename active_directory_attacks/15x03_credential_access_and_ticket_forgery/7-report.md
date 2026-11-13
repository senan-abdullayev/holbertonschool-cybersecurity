# Credential Access and Ticket Forgery — Domain Dominance Report

**Client:** Kessler Dynamics
**Domain assessed:** `kessler.local`
**Domain controller:** `KESSLER-DC01` (Windows Server 2022, Server Core) — `10.30.0.10`
**Engagement foothold:** `kessler.local\g.hale` (Domain-Admin-equivalent, replication rights, local admin on the DC)
**Classification of this document:** Domain-dominance / key-material compromise

---

## 0. Read this first (for the people who sign the cheque)

This engagement did not compromise an administrator account. It compromised the **domain's own cryptographic key material** — the keys the domain controller uses to decide who everybody is. An attacker who holds what we now hold does not log in as your administrators; they **manufacture administrators, services and users that your domain will believe unconditionally**, and they do it without touching any of those accounts' passwords.

The practical consequence: **resetting passwords does not remove this attacker, and neither does resetting the one account everybody thinks of resetting.** The cost of genuine eviction is a staged, time-boxed rebuild of trust across the whole domain, and the single most expensive mistake your team can make is to try to do it in one evening. The sections below say exactly why, and exactly what it costs.

This is a **finding of the most severe class**: total, persistent, forgeable control of the identity fabric. Treat it as an event, not a ticket in a queue.

---

## 1. The chain — what we did, in order, and the decision at each fork

Every step below started from the foothold we were given (`g.hale`). The point of the engagement was never "could we read the file" — with Domain-Admin-equivalent rights we trivially could. The point was **which technique we chose, and the trace each one leaves**, because that is what determines whether your detection programme ever sees it.

### Step 1 — Confirm the memory route is a dead end for the domain key
A credential dump against the DC's memory returns live logon sessions and machine/service material, but **not `krbtgt`** — the domain's master key account never interactively logs on, so its key is never resident in memory. **Decision:** stop pursuing memory for the domain key and pivot to the directory itself. This matters because it tells you where the real exposure is (the directory and its backup key), not the LSASS dump your EDR is watching.

### Step 2 — Take the directory's key material, two ways

- **By asking (replication / DCSync).** We used `g.hale`'s replication rights to ask the DC to send us credential material for specific principals, the way one domain controller asks another. We took only what the engagement needed: `krbtgt` (the domain master key) and the DC machine account.
  - **Why this way:** precise, immediate, no file access required.
  - **What it costs you in noise:** it writes a **very specific record** — see Detection, §4.
- **By taking the file (offline).** We also had the DC build an `ntdsutil` IFM snapshot — a copy of the directory database `NTDS.dit` plus the `SYSTEM` registry hive that holds its boot key — pulled both back, and decrypted the **entire** store offline, where nothing on the DC was watching.
  - **Why this way:** complete (every account, not just the ones you named) and silent at the point of decryption.
  - **What it costs you:** it requires code execution on the DC and leaves host-side artefacts there instead.

**The fork that matters:** these are not two ways of doing the same thing. One is *precise, live, and logged on the controller*; the other is *complete, offline, and demands you already be on the box*. A tester — or an attacker — who reaches for the same one every time has not made a decision. We used replication when we wanted two named identities quietly, and the offline route to prove the whole directory was ours.

### Step 3 — Abuse the domain DPAPI backup key
We extracted the **domain DPAPI backup key** — a single domain-level object that exists so the organisation is never permanently locked out of its staff's protected data. We used it to decrypt a target user's (`d.okoro`) DPAPI master key **without that user's password and without their cooperation**, and then opened their protected secret.
- **Decision / why the narrow path was wrong here:** we deliberately did **not** attack the user's own password-rooted protection chain. That chain is designed to resist exactly that and would have cost days. The domain hands you a master skeleton key instead. We took the key the domain offers, not the one the user guards.

### Step 4 — Silver ticket (the narrowest capability)
We forged a **single service ticket** for the file service on the DC, signed with that service's own key (the machine account key we took in Step 2), and used it to reach the service as `Administrator`.
- **Decision / why narrow was correct:** a service validates its own tickets. It does not ask the domain controller. So this reaches *one service, in one context* — and in exchange it is the **quietest** technique available: the KDC is never in the conversation. When one service is all the objective needs, this is the right answer precisely because of that limitation. We did not reach for the domain-wide forge to do a single-service job.

### Step 5 — Golden ticket, built the way this domain expects
We forged a domain-wide ticket (a TGT) for an existing identity, signed with the `krbtgt` key.
- **Decision:** we built it with **AES**, not RC4. The RC4 construction is the one every tutorial demonstrates; it still works, but on a current, AES-capable domain it is **conspicuous** — a TGT encrypted with an algorithm the account no longer prefers stands out. We also confirmed this build's KDC **rejects golden tickets minted for principals that do not exist**, so we forged for a real account. A forge that works *and announces itself* proves nothing; we built the quiet one.

### Step 6 — Diamond ticket (a genuine ticket with a lie in it)
We asked the domain for a **legitimate** TGT as `g.hale`, opened it with the `krbtgt` key, changed what it asserts about us (made the holder `Administrator`), and re-sealed it.
- **Decision / the size discipline:** this ticket's structure is entirely correct **because the domain built it** — it carries the domain's real lifetimes and shape. Detection tuned to tickets "assembled from scratch" does not see it. Its one weakness is size: the change we make has a footprint, and an over-stuffed ticket is abnormally large. We changed **exactly one group membership** and nothing more, keeping it the same size as its peers.

### Step 7 — Prove the reset does not evict
Kessler reset the `krbtgt` password once — exactly as you would on the morning you found us. A ticket we forged **before** that reset still authenticated **after** it. See §5 for why, and for what eviction actually costs.

---

## 2. What Kessler has lost — the secrets, and the standing authority each one carries

This section is deliberately **not** a list of what we did. It is a list of **what Kessler no longer controls**, and for each secret, the authority a holder keeps *after we are gone* — what they can **create or read later, offline, without asking anyone and without any fresh access or permission.**

**1. The domain's master signing key (`krbtgt`).**
This single key is what the domain uses to sign every authentication token it issues — it is the thing that makes a token "real."
*Standing authority of whoever holds it:* they can **manufacture a valid identity for anyone — any employee, any administrator, any service, any computer, even identities that do not exist yet — for any system, at any time.** They do this **offline, without contacting a domain controller, and without any account's password.** It is not a login and there is no session to expire. It keeps working **after you reset user passwords** (they simply mint a new token) and **after you reset `krbtgt` once** (see §5). Nothing short of rotating this one key *twice* removes the capability.

**2. Every account's keys in the directory (the whole `NTDS.dit`).**
We hold the secret key material for **every user, computer and service account in `kessler.local`** — the domain Administrator and the domain controller's own account included.
*Standing authority:* they can authenticate **as any named account directly**, with no password-guessing and no interaction, until **each individual account's password is changed** — tens or hundreds of separate resets, not one.

**3. A service's own key (the co-located service account / the DC's machine account).**
*Standing authority:* they can issue access tokens **for that service that the domain controller never sees and never approves** — invisible impersonation of that service's users — until **that specific account's key is rotated.**

**4. The domain DPAPI backup key.**
This is the organisation's master recovery key for **everything your staff protected with Windows' built-in data protection** — saved passwords, browser secrets, stored private keys and certificates.
*Standing authority:* they can **decrypt any employee's protected data, across the entire estate, past and future, without that employee's password and without their knowledge.** This is not impersonation — it is the **data itself**. It stays usable until the backup key is rotated *and* every protected secret is re-encrypted; anything already decrypted is simply gone.

**What this means on an ordinary Tuesday, with us no longer in the building:** a holder becomes the domain Administrator whenever they choose, reads any employee's stored secrets, and impersonates the service accounts that run your aerospace/defence systems — **generating their own permission each time, indefinitely, until the specific key behind each capability is retired.** They never "break in" again, because they do not need an account: they are the authority that issues accounts.

---

## 3. Credential against capability — why this is not a compromised administrator, and why the budget is different

If the mental model for this incident is "an admin account was stolen — reset it," that model is wrong by orders of magnitude, and the whole remediation budget depends on the board seeing why. This is not a worse version of the *same* problem; it is a **different kind** of problem. The difference shows on three axes:

| | **A stolen administrator account** | **The domain key material we now hold** |
|---|---|---|
| **Breadth** | Lets the attacker be **one identity** — that account, with exactly the rights it has. | Lets the attacker **be, or create, *any* identity** in the domain, **and read every user's protected data.** Not one account — all of them, including accounts that do not exist yet. |
| **Permission** | They **borrow** that account's existing access. If the account lacks a right, so do they; grant/deny still governs them. | They **do not use anyone's access — they mint their own.** Permission stops being a gate: they issue the tokens that *define* permission, offline. They never need fresh access again. |
| **Persistence** | Ends the moment the **session ends, the password is reset, or the account is disabled.** Revocation is **one action on one account.** | **Survives password resets** (forge a new token), **survives the account we first used** (we no longer need `g.hale`), and **survives the single `krbtgt` reset everyone reaches for first.** Only a **double key rotation plus a domain-wide credential reset** ends it. |

Put plainly: a stolen admin account is a **borrowed key to one door that you take back by changing the lock.** Domain key material is **the key-cutting machine and the master blank** — the holder cuts a key to any door at any time, and changing one lock does nothing. The two losses we inflicted map onto this exactly: the directory keys let us **be your people**; the DPAPI backup key gives us **what your people were keeping.** Neither depends on a password, so **no password reset recovers either.**

The budget consequence the board must internalise: recovering from a stolen administrator is **one reset, one afternoon.** Recovering from this is a **staged rotation of the domain's trust anchors, a reset of every credential those keys can forge, re-protection of all DPAPI-protected data, and a rebuild of the compromised controller** — and, as §5 shows, it **cannot be safely compressed into one maintenance window** without doing more damage than we did.

---

## 4. Detection — what each action recorded, and what it did not

The most useful thing we can tell you is which parts of this engagement your DC logs **cannot** show you, because a detection programme built entirely on the controller's logs has holes in exactly those places.

| Action | What it recorded | What it did **not** record |
|---|---|---|
| **DCSync (replication)** | **Event 4662** on the DC — an object-access event showing `g.hale` exercising the replication control-access rights (replication GUID `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`). This is **distinctive**: an ordinary account invoking directory replication is a high-fidelity alert. | Nothing hides it — this is the loud, catchable route. If you detect one thing from this report, detect this. |
| **Offline NTDS (IFM) extraction** | Host-side artefacts on the DC (snapshot creation, process execution). Visible to **endpoint/host** telemetry on the DC. | **No replication event (no 4662).** If you watch only directory/replication logs, the entire directory can leave the building without a directory-log trace. Detection has to be on the host. |
| **DPAPI backup-key abuse** | The retrieval of the backup key touches the DC; master-key decryption and the final unprotect happen **offline**. | The **decryption of the user's data is invisible to you** — it happens on our machine, not yours. You see (at most) the key retrieval, never the use. |
| **Silver ticket** | A logon on the **service host** (event 4624) when the ticket is used. | **No 4768 and no 4769 at all.** We confirmed this directly: zero ticket-request events were generated. The service validated our ticket with its own key; the KDC was never asked. **A detection programme built only on KDC ticket logs sees nothing here.** |
| **Golden ticket (AES)** | TGS requests (4769) when the forged TGT is used to reach services; **built with AES it blends in**. The RC4 variant would stand out by encryption type. | The **forging** of the TGT is invisible (done offline). Only its *use* generates service-ticket events, and those look legitimate. |
| **Diamond ticket** | A genuine AS exchange (the real TGT request as `g.hale`), then normal-looking use. | Because the ticket **is** a real domain-issued ticket with a modified payload, it carries correct structure and lifetimes. **Detection tuned to from-scratch forgeries does not flag it.** Its only tell is abnormal size — which we specifically avoided. |
| **krbtgt reset survival** | The password reset itself (4724/4738) is logged. | The fact that **our pre-reset ticket still works afterwards generates no alarm** — it is accepted as a normal authentication. |

**The headline for your SOC:** the replication route (4662) is your reliable catch. The **offline extraction, the silver ticket, and the DPAPI decryption are substantially or wholly invisible in the domain controller's own logs by design.** Those require host-based telemetry (DC endpoint monitoring) and service-host logon analysis — not KDC log review — to see at all.

---

## 5. Remediation and its price

### 5.1 Controls that reduce each route (before the fact)

| Route | Control that reduces it |
|---|---|
| Memory theft of live material | **Credential Guard** / LSA protection on the DC and privileged hosts; no reusable secrets left in memory. |
| DCSync / replication abuse | **Tiered administration** — replication rights confined to genuine DCs and a minimal, monitored admin tier; alert on 4662 replication GUIDs from non-DC principals. |
| Offline NTDS extraction | **Physical/host control of the DC** and DC endpoint monitoring; restrict and alert on `ntdsutil`/volume-snapshot/backup activity; protect backups of `NTDS.dit` as if they were the live directory (they are). |
| DPAPI backup-key abuse | Treat the **domain DPAPI backup key as a Tier-0 secret**; restrict and monitor its retrieval; understand that its compromise is estate-wide. |
| Silver ticket | **AES enforcement** and strong, rotated service-account/machine keys; service-side logon analysis (you cannot rely on the KDC to see it). |
| Golden / diamond ticket | **AES enforcement** (makes RC4 forges stand out) and `krbtgt` rotation hygiene; the diamond specifically is countered by watching ticket **size/structure anomalies**, not just scratch-built forgeries. |

### 5.2 The eviction itself — why the obvious version fails

**The obvious remediation — reset `krbtgt` once — does not evict the attacker.** We proved it: a ticket forged before the reset still authenticated after it.

The reason is deliberate, not a bug. A domain that invalidated every ticket in flight the instant this account changed would **break itself on a routine maintenance task**, so the KDC keeps **more than one `krbtgt` key alive at a time — the current key and the previous one (N and N-1).** We observed the key version move from **kvno 2 to kvno 3** on the single reset; the previous key (kvno 2) that signed our ticket remained honoured. **One reset only rolls the current key into the "previous" slot, where it still works.**

### 5.3 What genuine eviction requires

Eviction is **not one operation**:

1. **Rotate `krbtgt` twice**, so the attacker's key is pushed out of *both* the current and previous slots and is no longer honoured by any DC.
2. **Separate the two rotations by a mandatory interval** (below).
3. **Reset the rest of what was taken.** The double rotation invalidates forged *Kerberos tickets*, but it does **nothing** about:
   - the **service/machine key** behind the silver ticket (reset those accounts),
   - the **directory-wide credentials** we copied (force a domain-wide password reset, prioritising Tier-0, service and privileged accounts),
   - the **DPAPI backup key** exposure (the data already decrypted is gone; rotate/re-protect where feasible and treat exposed secrets as burned),
   - the **host(s)** we had code execution on — **rebuild/reimage the DC**; do not "clean" it.

### 5.4 Why the interval cannot be compressed

The interval between the two `krbtgt` rotations exists for **two separate reasons**, and both come from values the domain itself publishes:

- **Reason 1 — tickets in flight must expire.** Legitimate users hold TGTs signed with the key you are about to retire. This domain's own policy sets **MaxTicketAge = 10 hours** (max TGT lifetime) and **MaxRenewAge = 7 days** (max renewal). If you rotate the second time before legitimate tickets have aged out, **you invalidate every valid user's session at once** — a self-inflicted domain-wide authentication outage.
- **Reason 2 — the controllers must agree.** The first new key must **replicate to every domain controller** before the second rotation. If a DC has not yet received rotation #1 when rotation #2 lands, the DCs end up with **inconsistent `krbtgt` key histories**, and authentication fails unpredictably across the estate until replication is forced and converges.

**If someone compresses the interval because Friday night is nearly over**, they do not speed up the eviction — they **break the domain in a way that is considerably more expensive than the intrusion was**: either a mass logout of the entire workforce, or a split-brain Kerberos failure across domain controllers. The interval is a correctness requirement, not a courtesy. Budget for the wait; do not let an impatient change window remove it.

---

## 6. Closeout — every ticket and every piece of key material we produced or took

So Kessler can account for all of it. Everything below was generated or extracted during this engagement and must be considered compromised until the remediation in §5 is complete.

### Key material extracted
| Item | Identifier / notes |
|---|---|
| `krbtgt` key (domain master key) | NT `12a181c4a7d3d97d2ec7b6bac6194c21`, AES256 `91b329…e85939` — **kvno 2** (pre-reset). After Kessler's single reset the live key is **kvno 3** (`eed33f…`, AES256 `2cba66…`); the kvno-2 key is still honoured until a second rotation. |
| DC machine account key | `KESSLER-DC01$` — NT `32c55f5af4b2e293e246cc62af5e420f`, AES256 `b48362…` (used as the silver-ticket service key). |
| Service account key | `svc_sql` — NT `93fe346a6dd03735f0dd525d2e23aee1`, AES256 `2c8b50…`. |
| Domain Administrator credential | `Administrator` (RID 500) — NT hash recovered from the offline directory copy. |
| Foothold account credential | `g.hale` (RID 1103) — NT/AES keys recovered (we already held the password). |
| **Entire directory** | Full `NTDS.dit` + `SYSTEM` boot key extracted offline — **every** user/computer/service credential in `kessler.local` is compromised, not only those listed here. |
| Domain DPAPI backup key | `G$BCKUPKEY_23BB4235-D953-4F5D-82C9-EC5F6056991C` — exported as a PVK. **Estate-wide DPAPI recovery capability.** |
| User DPAPI master key | `d.okoro` master key `f0fc9333-3797-4414-b3db-a738d15f7fc3` (SID `…-1105`) — decrypted via the backup key; `d.okoro`'s protected data is exposed. |

### Tickets forged / produced
| Ticket | Identity asserted | Signed with | Purpose |
|---|---|---|---|
| Silver (service) | `Administrator` | DC machine account key | Reach the file service with no KDC contact. |
| Golden (TGT, AES) | `Administrator` (existing account) | `krbtgt` kvno-2 key | Domain-wide authentication, quiet (AES) construction. |
| Golden (TGT, RC4) | `Administrator` | `krbtgt` kvno-2 NT hash | Generated only to demonstrate the loud/detectable variant. |
| Diamond (modified TGT) | `Administrator` (from a real `g.hale` TGT) | `krbtgt` kvno-2 key | Genuine domain-issued ticket with a modified group membership. |
| Persistence proof (golden) | `Administrator` | `krbtgt` kvno-2 key | Forged before the reset; **confirmed still valid after it**. |

### Tooling placed on Kessler systems (and removed)
| Item | Location | Status |
|---|---|---|
| `Rubeus` (diamond-capable) | `C:\Windows\Temp\` on `KESSLER-DC01` | **Removed** at end of engagement. |
| `ntdsutil` IFM snapshot | `C:\Windows\Temp\ifm\` on `KESSLER-DC01` | **Removed**; VSS snapshot auto-dismounted (verified none remaining). |

### Residual state for Kessler to restore
- `krbtgt` is at **kvno 3** following the single reset performed for the persistence demonstration. The supported double-rotation eviction (§5) supersedes this; if restoring the environment to baseline instead, confirm `krbtgt` is returned to its original key.

---

## 7. Bottom line

Kessler has lost control of the key material that defines identity in `kessler.local`. This is a capability compromise, not a credential compromise: the attacker can be anyone and read anyone's protected data, indefinitely, and survives the reset everyone reaches for first. Genuine eviction is a **double `krbtgt` rotation with a mandatory, uncompressible interval, plus a domain-wide credential reset and a rebuild of the compromised controller** — and the fastest way to make this worse is to try to do the rotation in one night. Fund the staged procedure; do not fund the shortcut.
