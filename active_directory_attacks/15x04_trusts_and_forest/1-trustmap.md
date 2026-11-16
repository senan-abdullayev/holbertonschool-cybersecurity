# 1 — Trust Map of the Aldermont Estate

Enumerated live from `r.bello@corp.aldermont.local` (child-domain admin), cross-checked with
`netexec`. One entry per trust, each matched to the domains/forests that signed it. Parts B and C
are explicitly **not** trust fields.

## The three parties

| Domain | Role | DC | IP | Domain SID |
|--------|------|----|----|------------|
| `aldermont.local` | forest root | ALDER-ROOT-DC | 192.168.60.10 | `S-1-5-21-2656703115-1281281457-4105409538` |
| `corp.aldermont.local` | child domain (**foothold**) | ALDER-CHILD-DC | 192.168.60.11 | `S-1-5-21-566709512-1948993727-1589621289` |
| `trentham.local` | separate forest | TRENTHAM-DC | 192.168.60.20 | `S-1-5-21-3110737944-308097035-3889185375` |

## Completeness — why this inventory omits no trust

Trust enumeration here is **authoritative**, not a convenient subset, because of how AD stores
trusts:

1. **Every trust a forest holds is recorded as a `trustedDomain` object in its forest-root
   domain** — one for each child domain, and one for each external / forest / realm / shortcut
   trust. Enumerating `(objectClass=trustedDomain)` at the forest root therefore returns the
   *complete* trust set of the estate. The forest root `aldermont.local` **is** readable from the
   foothold, so completeness does not depend on reading any other DC.
2. **The LDAP filter applies no state or type restriction.** `(objectClass=trustedDomain)`
   returns every trust object regardless of whether it is enabled or disabled (closed),
   inbound/outbound/both, intra-forest or external, in-use or dormant. Nothing is filtered out
   for being "redundant, external, or less useful."

Enumerated at the forest root `aldermont.local` → exactly **two** trust objects:

```
trustPartner=corp.aldermont.local  trustDirection=3  trustType=2  trustAttributes=0x20
trustPartner=trentham.local        trustDirection=3  trustType=2  trustAttributes=0x8
```

Cross-checks that close every omission path:

- **No hidden domain (→ no hidden intra-forest trust).** The forest's `crossRef`/Partitions list
  (`CN=Partitions,CN=Configuration,DC=aldermont,DC=local`) contains exactly two domain NCs:
  `aldermont.local` and `corp.aldermont.local`. A third child domain would create another
  parent-child trust; there is none.
- **No external/realm/shortcut trust.** The only non-child trust at the root is the forest trust
  to `trentham.local` (`trustAttributes=0x8 FOREST_TRANSITIVE`). No object carries external
  (`0x40`), quarantine (`0x4`), or downlevel (`trustType=1`) markings; no realm (`trustType=3`)
  object exists.
- **Reciprocal sides are the same trusts, not extra ones.** `corp.aldermont.local` holds the
  partner object `CN=aldermont.local` (its parent) — the other side of the parent-child trust.
  `trentham.local` necessarily holds the partner object for the forest trust, but reading it is
  **not required for completeness**: Trentham's copy is the *same* Aldermont↔Trentham trust seen
  from the other end, and any trusts Trentham holds to *third* parties belong to a separate forest
  and are not trusts of the Aldermont estate.

**Conclusion: the estate holds exactly two trusts. Nothing was omitted for being closed,
redundant, external, or less useful.**

| # | Trust | Participants | Kind | Stored objects |
|---|-------|--------------|------|----------------|
| **T1** | parent–child | `corp.aldermont.local` ⇄ `aldermont.local` | intra-forest | `CN=aldermont.local` in corp; `CN=corp.aldermont.local` in root |
| **T2** | forest trust | `aldermont.local` ⇄ `trentham.local` | inter-forest | `CN=trentham.local` in root; reciprocal in Trentham (not read) |

---

## Part A — The four structural properties, per trust

**Direction vocabulary (consistent):** `trustDirection` is one field on one object, read from the
domain holding it — `1`=inbound (holder is trusted by partner), `2`=outbound (holder trusts
partner), `3`=bidirectional (one object carrying both components, read from its own value, not
inferred from the partner's object).
**Transitivity rule (consistent):** non-transitive **iff** `trustAttributes` has the
`NON_TRANSITIVE (0x1)` bit; transitive otherwise. Read from the attribute only.

### T1 — `corp.aldermont.local` ⇄ `aldermont.local` (parent–child)
- **Domains joined:** `corp.aldermont.local` and `aldermont.local`.
- **Direction — perspective `corp.aldermont.local`** (holds object `CN=aldermont.local`): outbound
  yes (`corp` trusts `aldermont`), inbound yes (`corp` is trusted by `aldermont`);
  `trustDirection=3` → **bidirectional**. (Root's own object `CN=corp.aldermont.local` likewise
  reads `3`.)
- **Type:** `trustType=2` → uplevel AD/Kerberos; `trustAttributes=0x20 (WITHIN_FOREST)`.
- **Transitive?** `0x20` has no `NON_TRANSITIVE (0x1)` bit → **transitive**.

### T2 — `aldermont.local` ⇄ `trentham.local` (forest trust)
- **Domains joined:** forest roots `aldermont.local` and `trentham.local`.
- **Direction — perspective `aldermont.local`** (holds object `CN=trentham.local`): outbound yes
  (`aldermont` trusts `trentham`), inbound yes (`aldermont` is trusted by `trentham`);
  `trustDirection=3` → **bidirectional**.
- **Type:** `trustType=2` → uplevel AD/Kerberos; `trustAttributes=0x8 (FOREST_TRANSITIVE)` → a
  forest trust.
- **Transitive?** `0x8` has no `NON_TRANSITIVE (0x1)` bit → **transitive** (the `FOREST_TRANSITIVE`
  bit names the transitive class).

---

> The sections below are **not** structural trust fields and do not re-derive anything in Part A.
> They are included only because the task asks for them.

## Part B — (not a trust field) what an identity crossing is subject to

By trust kind, not stored on the object:
- **T1** (within-forest, `0x20`): **no SID filtering** — SIDHistory / `ExtraSids` honoured.
- **T2** (forest trust, `0x8`): **SID filtering ON** — SIDs foreign to the trusted forest, and any
  SID with RID < 1000, are stripped from the inter-realm PAC. This is the one
  administratively-settable control in the map (relaxable via `netdom /enablesidhistory`); on this
  estate it is set to filter. Proven in the FLAG_FILTER task, not claimed as a crossing here.

## Part C — (not a trust field) reachable direction, access not assumed

"Reachable" = only the direction an authentication request may travel (per Part A); it asserts
**no** access to any resource (ACLs, not enumerated here):
- **T1:** authentication may traverse as Part A records; no SID filtering strips in-forest
  authority. Whether an identity can read an object is an ACL question, not claimed here.
- **T2:** authentication may traverse as Part A records, but SID filtering removes foreign /
  RID<1000 SIDs, so injected authority does not traverse — the trust **alone** grants no access
  into `trentham.local`. Consistent with that, an unprivileged bind by the foothold to TRENTHAM-DC
  is **refused** (`AcceptSecurityContext error, data 52e`).

### Boundary summary
The **domain** is not the security boundary — within `aldermont.local`, T1 carries authority
between child and root unfiltered. The **forest** is the boundary that holds — SID filtering on
T2 strips injected authority, so no `trentham.local` resource is reachable on the strength of the
trust itself.

> FLAG_TRUSTMAP — located at `\\ALDER-ROOT-DC\proof$\trustmap.txt`: `ALD{f05f5d1ffdcf5a577ce31756e43ff5ed}`
