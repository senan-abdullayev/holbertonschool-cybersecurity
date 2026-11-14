# 1 — Trust Map of the Aldermont Estate

Enumerated live from `r.bello@corp.aldermont.local` (child-domain admin), reading the
`trustedDomain` objects on each DC with `ldapsearch` and cross-checked with `netexec`. Every
edge was treated as a hypothesis and confirmed against the directory as it stands now.

Two things are kept strictly apart in this document:

- **Structure** — the four properties that *define* each trust: which domains it joins,
  its direction, its type, and its transitivity. These come only from the trust object.
- **Consequence** — what structure *produces*: the SID-filtering behaviour an identity meets
  when crossing, and what is therefore reachable. Direction is **never** read as access.

## The three parties

| Domain | Role | DC | IP | Domain SID |
|--------|------|----|----|------------|
| `aldermont.local` | forest root | ALDER-ROOT-DC | 192.168.60.10 | `S-1-5-21-2656703115-1281281457-4105409538` |
| `corp.aldermont.local` | child of the root (**foothold**) | ALDER-CHILD-DC | 192.168.60.11 | `S-1-5-21-566709512-1948993727-1589621289` |
| `trentham.local` | separate, **acquired** forest | TRENTHAM-DC | 192.168.60.20 | `S-1-5-21-3110737944-308097035-3889185375` |

---

## Part A — The four structural properties (from the trust object only)

| Trust | 1. Domains joined | 2. Direction | 3. Type | 4. Transitivity |
|-------|-------------------|--------------|---------|-----------------|
| **T1** | `corp.aldermont.local` — `aldermont.local` | `trustDirection=3` → **bidirectional** | `trustType=2` → **uplevel (AD/Kerberos)** | **transitive** — `trustAttributes=0x20`, `WITHIN_FOREST`, no `NON_TRANSITIVE (0x1)` bit |
| **T2** | `aldermont.local` — `trentham.local` | `trustDirection=3` → **bidirectional** | `trustType=2` → **uplevel (AD/Kerberos)** | **transitive** — `trustAttributes=0x8`, `FOREST_TRANSITIVE`, no `NON_TRANSITIVE (0x1)` bit |

Property definitions used, applied consistently:

- **Direction** is `trustDirection`: `1`=inbound, `2`=outbound, `3`=bidirectional. Both trusts
  are `3`. Bidirectional means **each side may authenticate principals of the other**. It is a
  statement about authentication flow only — it says nothing about what any principal is
  authorised to do. (The access question is Part C.)
- **Type** is `trustType`: `2`=uplevel (Windows AD). Both trusts are AD/Kerberos trusts. T2 was
  established specifically as a *forest* trust (see the `FOREST_TRANSITIVE` attribute below).
- **Transitivity** is read **only** from `trustAttributes`. Neither object carries the
  `NON_TRANSITIVE (0x00000001)` bit, so both are transitive. The *class* of transitivity is
  named by the bit present — `WITHIN_FOREST (0x20)` for T1, `FOREST_TRANSITIVE (0x8)` for T2 —
  but the property being asserted here is simply: **transitive, yes.**

## Part B — The property enumeration does not print: what crossing is subject to

The task calls this "the property that decides everything else." It is not a field on the trust
object; it follows from the trust **kind**, with one administratively-set exception.

| Trust | Kind | Identity crossing is subject to |
|-------|------|---------------------------------|
| **T1** `corp` — `aldermont` | within-forest (`0x20`) | **No SID filtering.** SIDHistory / `ExtraSids` are honoured. |
| **T2** `aldermont` — `trentham` | forest trust (`0x8`) | **SID filtering is ON.** SIDs foreign to the trusted forest, and any SID with RID < 1000, are stripped from the inter-realm PAC. |

**The trust that was changed from its default.** SID-filtering behaviour otherwise maps onto
the trust *kind*, not an administrator's choice — within-forest never filters, a forest trust
does. T2 is the exception the task points at: it is the single trust whose filtering is an
**administrative control** (it can be relaxed with `netdom /enablesidhistory`), and on this
estate it has been **set/left to filter**. That setting is what makes the forest edge behave
differently from the structurally-identical-looking direction/type/transitivity it shares with
T1. The *effect* of the strip is proven in the FLAG_FILTER task — it is **not** claimed as a
crossing here.

## Part C — Reachability (consequence of structure + ACLs, not a trust property)

Reachability is **direction constrained by SID filtering and by existing ACLs** — never
direction alone.

- **T1 — `corp` ⇄ `aldermont`:** no filtering in the way. With the foothold, `r.bello`
  authenticates to ALDER-ROOT-DC, reads its directory, and reads the `proof$` share (verified).
  The EA-gated `C:\RootOnly` objective is **not** reachable yet — it needs the Enterprise Admins
  SID the foothold does not hold. Because T1 does not filter, that SID can later be injected via
  `ExtraSids` and the root will honour it.
- **T2 — `aldermont` ⇄ `trentham`:** the direction being **bidirectional** means Trentham *may*
  authenticate an Aldermont principal — it does **not** grant that principal any rights.
  Authorisation is separate and, for the foothold, absent: an LDAP bind as
  `r.bello@corp.aldermont.local` against TRENTHAM-DC is rejected (`AcceptSecurityContext error,
  data 52e`). Verified: the foothold has **no standing access** into `trentham.local`. The one
  authorised path is an Aldermont universal group — a leftover acquisition grant — that already
  holds rights on a Trentham resource; its SID is native to the trusted forest, so SID filtering
  does not strip it.

**Direction vs access, stated once and used consistently:** every trust here is
*bidirectional* (a structural fact, Part A). *Bidirectional direction is not authorisation* —
it governs who may attempt authentication, not what they may reach. Where the graph shows two
arrows, access still depends on Part B (filtering) and on ACLs (Part C). Reading "bidirectional"
as "reachable both ways" is the error this map refuses to make.

### Boundary summary
The **domain** is not the security boundary — inside `aldermont.local` the child DA reaches the
root with no filtering between them (T1). The **forest** is the boundary that holds — SID
filtering on the T2 forest trust stops the same technique and forces the one narrow, legitimate
door.

> FLAG_TRUSTMAP (read from `\\ALDER-ROOT-DC\proof$\trustmap.txt` with the foothold): `ALD{f05f5d1ffdcf5a577ce31756e43ff5ed}`
