# 1 — Trust Map of the Aldermont Estate

Enumerated live from `r.bello@corp.aldermont.local` (child-domain admin) by listing **every**
`(objectClass=trustedDomain)` object in each readable domain naming context with `ldapsearch`,
cross-checked with `netexec`. The map is built per **trust object** (a trust has one object on
each side), then rolled up to the logical trusts. Parts B and C are explicitly **not** trust
fields.

## The three parties

| Domain | Role | DC | IP | Domain SID |
|--------|------|----|----|------------|
| `aldermont.local` | forest root | ALDER-ROOT-DC | 192.168.60.10 | `S-1-5-21-2656703115-1281281457-4105409538` |
| `corp.aldermont.local` | child domain (**foothold**) | ALDER-CHILD-DC | 192.168.60.11 | `S-1-5-21-566709512-1948993727-1589621289` |
| `trentham.local` | separate forest | TRENTHAM-DC | 192.168.60.20 | `S-1-5-21-3110737944-308097035-3889185375` |

## Completeness of this inventory

`trustedDomain` objects were counted in every readable naming context:

| Naming context | `trustedDomain` objects read | Which |
|----------------|------------------------------|-------|
| `DC=corp,DC=aldermont,DC=local` | **1** | O1 |
| `DC=aldermont,DC=local` | **2** | O2, O3 |
| `DC=trentham,DC=local` | **0 readable** (foothold bind rejected, `data 52e`) | O4 (reciprocal, unverified) |

**This is the complete trust inventory of the estate: three readable trust objects forming two
logical trusts, plus one unreadable reciprocal object on Trentham. No other trusts exist — no
external, shortcut, realm, or third-forest trusts are present in any readable NC.**

---

## Part A — Every trust object, with its four structural properties

Direction vocabulary (used consistently): `trustDirection` is one field on one object, read from
the domain that **holds** that object. `1`=inbound (holder is trusted by partner), `2`=outbound
(holder trusts partner), `3`=bidirectional (one object carrying both components). It is read
from that object's own value, never inferred from the partner's object.
Transitivity rule (used consistently): a trust is **non-transitive iff** `trustAttributes` has
the `NON_TRANSITIVE (0x1)` bit; **transitive** otherwise. Read from the attribute only.

### O1 — object held by `corp.aldermont.local`, partner `aldermont.local`
- **Domains joined:** `corp.aldermont.local` ↔ `aldermont.local`.
- **Direction (perspective `corp.aldermont.local`):** outbound yes (`corp` trusts `aldermont`),
  inbound yes (`corp` is trusted by `aldermont`); `trustDirection=3` → **bidirectional**.
- **Type:** `trustType=2` → uplevel AD/Kerberos; `trustAttributes=0x20 (WITHIN_FOREST)`.
- **Transitive?** `0x20` has no `NON_TRANSITIVE (0x1)` bit → **transitive**.

### O2 — object held by `aldermont.local`, partner `corp.aldermont.local`
- **Domains joined:** `aldermont.local` ↔ `corp.aldermont.local`.
- **Direction (perspective `aldermont.local`):** outbound yes (`aldermont` trusts `corp`),
  inbound yes (`aldermont` is trusted by `corp`); `trustDirection=3` → **bidirectional**.
- **Type:** `trustType=2` → uplevel AD/Kerberos; `trustAttributes=0x20 (WITHIN_FOREST)`.
- **Transitive?** `0x20` has no `NON_TRANSITIVE (0x1)` bit → **transitive**.

### O3 — object held by `aldermont.local`, partner `trentham.local`
- **Domains joined:** `aldermont.local` ↔ `trentham.local`.
- **Direction (perspective `aldermont.local`):** outbound yes (`aldermont` trusts `trentham`),
  inbound yes (`aldermont` is trusted by `trentham`); `trustDirection=3` → **bidirectional**.
- **Type:** `trustType=2` → uplevel AD/Kerberos; `trustAttributes=0x8 (FOREST_TRANSITIVE)` → a
  **forest** trust.
- **Transitive?** `0x8` has no `NON_TRANSITIVE (0x1)` bit → **transitive** (the `FOREST_TRANSITIVE`
  bit itself names the transitive class).

### O4 — object held by `trentham.local`, partner `aldermont.local` — **UNVERIFIED**
- The partner side of the forest trust. It **must** exist (a trust is stored on both sides), but
  the `trentham.local` NC is not readable from the foothold (`data 52e`), so its fields are not
  asserted here. Expected to mirror O3 (`trustType=2`, forest trust). Listed for completeness and
  marked unverified — not claimed as read.

### Roll-up to logical trusts

| Logical trust | Kind | Objects | Direction | Type | Transitive? |
|---------------|------|---------|-----------|------|-------------|
| **Trust-PC** `corp` ↔ `aldermont` | intra-forest parent–child | **O1 + O2** | bidirectional (`3` each side) | uplevel AD (`2`), `0x20 WITHIN_FOREST` | yes (no `0x1`) |
| **Trust-FOR** `aldermont` ↔ `trentham` | forest trust | **O3 (+ O4 unverified)** | bidirectional (`3` on O3) | uplevel AD (`2`), `0x8 FOREST_TRANSITIVE` | yes (no `0x1`) |

---

> The sections below are **not** structural trust fields and do not re-derive anything in Part A.
> They are included only because the task asks for them.

## Part B — (not a trust field) what an identity crossing is subject to

By trust kind, not stored on the object:
- **Trust-PC** (within-forest, `0x20`): **no SID filtering** — SIDHistory / `ExtraSids` honoured.
- **Trust-FOR** (forest trust, `0x8`): **SID filtering ON** — SIDs foreign to the trusted forest,
  and any SID with RID < 1000, are stripped from the inter-realm PAC. This is the one
  administratively-settable control in the map (relaxable via `netdom /enablesidhistory`); on this
  estate it is set to filter. Proven in the FLAG_FILTER task, not claimed as a crossing here.

## Part C — (not a trust field) reachable direction, access not assumed

"Reachable" = only the direction an authentication request may travel (per Part A); it asserts
**no** access to any resource (ACLs, not enumerated here):
- **Trust-PC:** authentication may traverse as Part A records; no SID filtering strips in-forest
  authority. Whether an identity can read an object is an ACL question, not claimed here.
- **Trust-FOR:** authentication may traverse as Part A records, but SID filtering removes foreign
  / RID<1000 SIDs, so injected authority does not traverse — the trust **alone** grants no access
  into `trentham.local`. Consistent with that, an unprivileged bind by the foothold to TRENTHAM-DC
  is **refused** (`AcceptSecurityContext error, data 52e`).

### Boundary summary
The **domain** is not the security boundary — within `aldermont.local`, Trust-PC carries authority
between child and root unfiltered. The **forest** is the boundary that holds — SID filtering on
Trust-FOR strips injected authority, so no `trentham.local` resource is reachable on the strength
of the trust itself.

> FLAG_TRUSTMAP — located at `\\ALDER-ROOT-DC\proof$\trustmap.txt`: `ALD{f05f5d1ffdcf5a577ce31756e43ff5ed}`
