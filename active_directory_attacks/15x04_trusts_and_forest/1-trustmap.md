# 1 — Trust Map of the Aldermont Estate

Enumerated live from `r.bello@corp.aldermont.local` (child-domain admin), reading the
`trustedDomain` objects on each DC with `ldapsearch` and cross-checked with `netexec`. Every
edge was treated as a hypothesis and confirmed against the directory.

## The three parties

| Domain | Role | DC | IP | Domain SID |
|--------|------|----|----|------------|
| `aldermont.local` | forest root | ALDER-ROOT-DC | 192.168.60.10 | `S-1-5-21-2656703115-1281281457-4105409538` |
| `corp.aldermont.local` | child domain (**foothold**) | ALDER-CHILD-DC | 192.168.60.11 | `S-1-5-21-566709512-1948993727-1589621289` |
| `trentham.local` | separate forest | TRENTHAM-DC | 192.168.60.20 | `S-1-5-21-3110737944-308097035-3889185375` |

---

## Part A — The four structural properties

These are read **only** from the trust object. No property below depends on, or implies, what
any identity is *authorised* to do — access is Part C and is kept entirely separate.

| Trust | 1. Domains joined | 2. Direction | 3. Type | 4. Transitivity |
|-------|-------------------|--------------|---------|-----------------|
| **T1** | `corp.aldermont.local` ↔ `aldermont.local` | `trustDirection=3` → **two-way** | `trustType=2` → **uplevel (AD) parent–child** | **transitive** |
| **T2** | `aldermont.local` ↔ `trentham.local` | `trustDirection=3` → **two-way** | `trustType=2` → **uplevel (AD) forest trust** | **transitive** |

**1. Domains joined.** T1 joins the child `corp.aldermont.local` and its parent `aldermont.local`.
T2 joins the two forest roots `aldermont.local` and `trentham.local`.

**2. Direction — stated from a named perspective.** A trust has a *trusted* side and a *trusting*
side; `trustDirection` encodes this from the perspective of the domain that **holds** the object:
`1`=inbound, `2`=outbound, `3`=both. Read from corp's object, T1's direction to `aldermont.local`
is `3` → inbound **and** outbound = **two-way**; the partner object on `aldermont`'s side reads `3`
likewise. Read from aldermont's object, T2's direction to `trentham.local` is `3` → **two-way**.
Direction is a property of the trust alone; it is not read here as access.

**3. Type.** `trustType=2` on both → uplevel Windows (AD/Kerberos). T1 is an intra-forest
parent–child trust (`trustAttributes` carries `WITHIN_FOREST, 0x20`). T2 is a forest trust
(`trustAttributes` carries `FOREST_TRANSITIVE, 0x8`).

**4. Transitivity — derived from type + `trustAttributes` only.**
- **T1 is transitive**: it is an intra-forest parent–child trust (type `2`, `trustAttributes=0x20`
  `WITHIN_FOREST`), a class that is transitive by definition, and the object carries no
  `NON_TRANSITIVE (0x1)` bit.
- **T2 is transitive**: it is a forest trust (type `2`, `trustAttributes=0x8` `FOREST_TRANSITIVE`),
  a class that is transitive by definition, and the object carries no `NON_TRANSITIVE (0x1)` bit.

Nothing in this derivation rests on roles, history, or how far anything can be reached — only on
the trust's type and attribute bits.

---

## Part B — The property enumeration does not print: what crossing is subject to

This is **not** a field on the trust object; it follows from the trust **kind** (Part A, property
3/4), with one administratively-set exception.

| Trust | Kind | Identity crossing it is subject to |
|-------|------|------------------------------------|
| **T1** | within-forest (`0x20`) | **No SID filtering** — SIDHistory / `ExtraSids` are honoured. |
| **T2** | forest trust (`0x8`) | **SID filtering is ON** — SIDs foreign to the trusted forest, and any SID with RID < 1000, are stripped from the inter-realm PAC. |

**The trust changed from its default.** SID-filtering behaviour maps onto trust *kind*, not an
administrator's choice — a within-forest trust never filters, a forest trust does. T2 is the one
trust whose filtering is also an *administrative control* (relaxable with `netdom
/enablesidhistory`); on this estate it is set to filter. That is the single
non-kind-determined setting in the map; its effect is proven in the FLAG_FILTER task and is
**not** claimed as a crossing here.

---

## Part C — Reachability (consequence, not a trust property)

Direction (Part A) says who may *attempt* authentication; it is **never** access. Reachability =
direction **constrained by** SID filtering (Part B) **and** existing ACLs.

- **T1:** no filtering between child and root. With the foothold, `r.bello` authenticates to
  ALDER-ROOT-DC, reads its directory, and reads the `proof$` share (verified). The EA-gated
  `C:\RootOnly` objective is not reachable yet — it needs the Enterprise Admins SID, which T1's
  lack of filtering lets us inject later via `ExtraSids`.
- **T2:** two-way direction does **not** make Trentham reachable from the foothold. Verified — an
  LDAP bind as `r.bello@corp.aldermont.local` against TRENTHAM-DC is rejected
  (`AcceptSecurityContext error, data 52e`): no standing rights. The only authorised path is an
  Aldermont universal group holding rights on a Trentham resource, whose SID is native to the
  trusted forest and so survives SID filtering.

### Boundary summary
The **domain** is not the security boundary — inside `aldermont.local` the child DA reaches the
root with no filtering (T1). The **forest** is the boundary that holds — SID filtering on the T2
forest trust stops the same technique and forces the one narrow, legitimate door.

> FLAG_TRUSTMAP (read from `\\ALDER-ROOT-DC\proof$\trustmap.txt` with the foothold): `ALD{f05f5d1ffdcf5a577ce31756e43ff5ed}`
