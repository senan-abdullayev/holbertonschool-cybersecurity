# 1 — Trust Map of the Aldermont Estate

Enumerated live from `r.bello@corp.aldermont.local` (child-domain admin), reading the
`trustedDomain` objects on each domain controller with `ldapsearch` and cross-checked with
`netexec`. Graph edges were treated as hypotheses and confirmed against the directory as it
stands now.

## The three parties

| Domain | Role | DC | IP | Domain SID |
|--------|------|----|----|------------|
| `aldermont.local` | forest root | ALDER-ROOT-DC | 192.168.60.10 | `S-1-5-21-2656703115-1281281457-4105409538` |
| `corp.aldermont.local` | child of the root (**foothold**) | ALDER-CHILD-DC | 192.168.60.11 | `S-1-5-21-566709512-1948993727-1589621289` |
| `trentham.local` | separate, **acquired** forest | TRENTHAM-DC | 192.168.60.20 | `S-1-5-21-3110737944-308097035-3889185375` |

## Summary

| Trust | Direction | Type | Transitive? | Identity crossing is subject to |
|-------|-----------|------|-------------|---------------------------------|
| `corp` ⇄ `aldermont` | bidirectional (`trustDirection=3`) | AD/uplevel (`trustType=2`) | yes — **within-forest** (`trustAttributes=0x20`) | **nothing** — no SID filtering |
| `aldermont` ⇄ `trentham` | bidirectional (`trustDirection=3`) | AD/uplevel (`trustType=2`) | yes — **forest-transitive** (`trustAttributes=0x8`) | **SID filtering** — foreign / RID<1000 SIDs stripped |

The decisive property — *what happens to an identity that travels across the trust* — is not
printed by any enumeration command. It is implied by the trust **kind**: a within-forest trust
applies no SID filtering, a forest trust does. That single difference is the whole engagement.

---

## Trust 1 — `corp.aldermont.local` ⇄ `aldermont.local` (parent ↔ child)

- **Which domains it joins:** the child `corp.aldermont.local` and its forest root `aldermont.local`.
- **Direction:** `trustDirection = 3` → **bidirectional**. Auto-created with the child.
- **Type:** `trustType = 2` → uplevel Windows/Kerberos (AD) trust.
- **Transitivity:** `trustAttributes = 0x20` (`WITHIN_FOREST`) → **transitive**; it is part of the forest, not a standalone link.
- **What an identity crossing it is subject to:** **no SID filtering.** SIDHistory and `ExtraSids` are honoured. This is the lever: an inter-realm TGT forged from the **child** `krbtgt` (via DCSync) carrying the root's **Enterprise Admins** SID in `ExtraSids` is accepted by ALDER-ROOT-DC, because intra-forest the forest root does not filter SIDs minted inside its own forest.
- **Reachable from where:** fully both ways. Verified — `r.bello` authenticates to ALDER-ROOT-DC, reads its directory, and reads the read-only `proof$` share. The EA-gated `C:\RootOnly` objective is **not** yet reachable; that requires the Enterprise Admins SID the foothold does not yet hold.

## Trust 2 — `aldermont.local` ⇄ `trentham.local` (forest trust)

- **Which domains it joins:** the two **forest roots** `aldermont.local` and `trentham.local`. `trentham.local` is a separate forest, acquired by Aldermont (its trust object was created later than the intra-forest one — `whenCreated 2026-10-04 15:01` vs `14:13`).
- **Direction:** `trustDirection = 3` → **bidirectional**.
- **Type:** `trustType = 2` → uplevel AD trust, established as a **forest** trust.
- **Transitivity:** `trustAttributes = 0x8` (`FOREST_TRANSITIVE`) → transitive **within the scope of the forest trust** — it covers each forest's child domains (so `corp` is inside its reach), but it does **not** chain onward to any third forest Trentham might trust.
- **What an identity crossing it is subject to:** **SID filtering (ON).** This is the one trust whose security posture is an administrative control rather than a structural given, and it has been set to filter — the forest trust's default-and-configured state. At this edge the inter-realm PAC is stripped of any SID that is **foreign to the trusted forest** or has **RID < 1000**. The Trust-1 trick (inject the EA SID via `ExtraSids`/SIDHistory) therefore **fails here** — the injected SID is dropped, not honoured. The *only* thing that survives is a SID that genuinely belongs to the trusted Aldermont forest: the leftover acquisition grant — an Aldermont universal group that already holds rights on a Trentham resource. (Proof of the strip is the FLAG_FILTER task; it is **not** claimed as crossed here.)
- **Reachable from where:** **not a two-way road.** `trustDirection = 3` means both forests can *authenticate* principals across the link — it does **not** mean `r.bello` is *authorised* into Trentham. Verified: an LDAP bind as `r.bello@corp.aldermont.local` against TRENTHAM-DC (192.168.60.20) is rejected (`AcceptSecurityContext error, data 52e`). The foothold has zero standing rights in `trentham.local`. The single traversable door is membership of the Aldermont group that the acquisition left holding rights on `\\TRENTHAM-DC\crown`.

---

## Plain statement of what is reachable from where

- **corp → aldermont (root):** reachable both directions, no filtering. Authentication and (post-escalation) full authority flow; the EA-SID forge from Trust 1 is honoured, which is how the root objective is reached.
- **corp/aldermont → trentham:** authentication can traverse the forest trust, but **authority cannot be injected** — SID filtering strips it. Reachable *only* through the pre-existing Aldermont group whose SID is native to the trusted forest and already carries rights on a Trentham resource.
- **A bidirectional trust is not a two-way road.** Direction governs who may *ask* to authenticate; SID filtering and existing ACLs govern what that identity may *do*. Reading this file as "two arrows = go anywhere" is the mistake that every later task would inherit.

### Boundary summary
The **domain** is not the security boundary — within `aldermont.local` the child DA escalates to the root with no SID filtering in the way. The **forest** is the boundary that holds: SID filtering on the Trentham forest trust is what stops the same technique and forces the one narrow, legitimate door.

> FLAG_TRUSTMAP (read from `\\ALDER-ROOT-DC\proof$\trustmap.txt` with the foothold): `ALD{f05f5d1ffdcf5a577ce31756e43ff5ed}`
