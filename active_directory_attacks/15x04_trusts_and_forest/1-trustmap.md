# 1 — Trust Map of the Aldermont Estate

Enumerated live from `r.bello@corp.aldermont.local` (child-domain admin), reading each
`trustedDomain` object with `ldapsearch` and cross-checked with `netexec`. Every field below is
taken from the trust object itself.

## The three parties

| Domain | Role | DC | IP | Domain SID |
|--------|------|----|----|------------|
| `aldermont.local` | forest root | ALDER-ROOT-DC | 192.168.60.10 | `S-1-5-21-2656703115-1281281457-4105409538` |
| `corp.aldermont.local` | child domain (**foothold**) | ALDER-CHILD-DC | 192.168.60.11 | `S-1-5-21-566709512-1948993727-1589621289` |
| `trentham.local` | separate forest | TRENTHAM-DC | 192.168.60.20 | `S-1-5-21-3110737944-308097035-3889185375` |

---

## Part A — The four structural properties

Every value below is read **only** from the trust object (`trustPartner`, `trustDirection`,
`trustType`, `trustAttributes`). Access and reachability are **not** structural properties and
are handled separately in Parts B and C.

### Direction vocabulary (used consistently throughout)
`trustDirection` is read from the perspective of the domain that **holds** the object:
- **inbound** (`1`) — the holding domain is *trusted by* the partner.
- **outbound** (`2`) — the holding domain *trusts* the partner.
- **bidirectional** (`3`) — both inbound and outbound on the same object.

A trust's direction is read from its own `trustDirection` value; it is never concluded from the
fact that a partner object also exists.

| Trust | 1. Domains joined | 2. Direction | 3. Type | 4. Transitive? |
|-------|-------------------|--------------|---------|----------------|
| **T1** | `corp.aldermont.local` — `aldermont.local` | **bidirectional** (`trustDirection=3`) | **uplevel AD, parent–child** (`trustType=2`, `trustAttributes` `WITHIN_FOREST 0x20`) | **yes — transitive** |
| **T2** | `aldermont.local` — `trentham.local` | **bidirectional** (`trustDirection=3`) | **uplevel AD, forest trust** (`trustType=2`, `trustAttributes` `FOREST_TRANSITIVE 0x8`) | **yes — transitive** |

**1. Domains joined.** T1 joins the child `corp.aldermont.local` and its parent
`aldermont.local`. T2 joins the two forest roots `aldermont.local` and `trentham.local`.

**2. Direction (from a named perspective).**
- **T1** — object held by `corp.aldermont.local`, partner `aldermont.local`: `trustDirection=3`
  → **bidirectional** (inbound and outbound).
- **T2** — object held by `aldermont.local`, partner `trentham.local`: `trustDirection=3`
  → **bidirectional** (inbound and outbound).

**3. Type.** `trustType=2` on both → **uplevel Windows (AD/Kerberos)**. The `trustAttributes`
bit distinguishes the sub-kind: T1 carries `WITHIN_FOREST (0x20)` → intra-forest parent–child;
T2 carries `FOREST_TRANSITIVE (0x8)` → forest trust.

**4. Transitivity (derived only from `trustType` + `trustAttributes`).**
- **T1 — transitive.** `trustType=2` with `trustAttributes=0x20 (WITHIN_FOREST)` and **no**
  `NON_TRANSITIVE (0x1)` bit. Within-forest trusts are transitive by configuration.
- **T2 — transitive.** `trustType=2` with `trustAttributes=0x8 (FOREST_TRANSITIVE)` and **no**
  `NON_TRANSITIVE (0x1)` bit. Forest trusts are transitive by configuration.

Each verdict comes from the object's own `trustType` and `trustAttributes` bits — not from the
number of domains present and not from any reachability result.

---

## Part B — Not a structural property: what an identity crossing is subject to

This is **not** one of the four fields above and is not stored on the trust object. It follows
from the trust kind (Part A property 3), with one administratively-set exception.

| Trust | Kind | Identity crossing it is subject to |
|-------|------|------------------------------------|
| **T1** | within-forest (`0x20`) | **No SID filtering** — SIDHistory / `ExtraSids` honoured. |
| **T2** | forest trust (`0x8`) | **SID filtering ON** — SIDs foreign to the trusted forest, and any SID with RID < 1000, stripped from the inter-realm PAC. |

**The trust changed from its default.** SID filtering maps onto trust kind — a within-forest
trust never filters, a forest trust does — except T2's filtering is also an administrative
control (relaxable with `netdom /enablesidhistory`); on this estate it is set to filter. Its
effect is proven in the FLAG_FILTER task and is **not** claimed as a crossing here.

---

## Part C — Not a structural property: reachability

Reachability is a *consequence* of Part A direction **plus** Part B filtering **plus** existing
ACLs. Bidirectional direction is authentication capability, never authorisation.

- **T1:** with the foothold, `r.bello` authenticates to ALDER-ROOT-DC, reads its directory, and
  reads the `proof$` share (verified). `C:\RootOnly` stays gated until the Enterprise Admins SID
  is injected via `ExtraSids` (which T1's lack of filtering permits).
- **T2:** bidirectional direction does **not** make Trentham reachable from the foothold —
  verified, an LDAP bind as `r.bello@corp.aldermont.local` against TRENTHAM-DC is rejected
  (`AcceptSecurityContext error, data 52e`), i.e. no standing rights. The one authorised path is
  an Aldermont universal group holding rights on a Trentham resource, whose SID is native to the
  trusted forest and survives SID filtering.

### Boundary summary
The **domain** is not the security boundary — inside `aldermont.local` the child DA reaches the
root unfiltered (T1). The **forest** is the boundary that holds — SID filtering on the T2 forest
trust stops the same technique and forces the one narrow, legitimate door.

> FLAG_TRUSTMAP (read from `\\ALDER-ROOT-DC\proof$\trustmap.txt` with the foothold): `ALD{f05f5d1ffdcf5a577ce31756e43ff5ed}`
