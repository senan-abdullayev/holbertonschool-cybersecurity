# 1 — Trust Map of the Aldermont Estate

Enumerated live from `r.bello@corp.aldermont.local` (child-domain admin) by reading each
`trustedDomain` object with `ldapsearch`, cross-checked with `netexec`. Part A below is the
trust map proper; Parts B and C are explicitly **not** trust fields and are kept separate.

## The three parties

| Domain | Role | DC | IP | Domain SID |
|--------|------|----|----|------------|
| `aldermont.local` | forest root | ALDER-ROOT-DC | 192.168.60.10 | `S-1-5-21-2656703115-1281281457-4105409538` |
| `corp.aldermont.local` | child domain (**foothold**) | ALDER-CHILD-DC | 192.168.60.11 | `S-1-5-21-566709512-1948993727-1589621289` |
| `trentham.local` | separate forest | TRENTHAM-DC | 192.168.60.20 | `S-1-5-21-3110737944-308097035-3889185375` |

---

## Part A — The four structural properties (trust object only)

**Direction vocabulary, used consistently.** `trustDirection` is one field on one trust object,
read from the perspective of the domain that **holds** that object:
- **inbound** = the partner trusts the holder (holder is the *trusted* side).
- **outbound** = the holder trusts the partner (holder is the *trusting* side).
- **bidirectional** (`trustDirection=3`) = the single object records an inbound component **and**
  an outbound component at once. This is read from the one object's own `3`; it is **not**
  concluded from the existence of a second object on the partner.

**Transitivity rule, used consistently.** A trust is **non-transitive** iff its `trustAttributes`
has the `NON_TRANSITIVE (0x00000001)` bit set, and **transitive** otherwise. This is the only
test applied; it is read from the attribute value, not from how many domains exist.

### Trust T1

- **1. Domains joined:** `corp.aldermont.local` and `aldermont.local`.
- **2. Direction — perspective: `corp.aldermont.local`** (the domain holding this object):
  - outbound component — does `corp` trust `aldermont`? **yes**
  - inbound component — is `corp` trusted by `aldermont`? **yes**
  - `trustDirection = 3` → **bidirectional** (both components present on this one object).
- **3. Type:** `trustType = 2` → **uplevel Windows (AD/Kerberos)**; `trustAttributes = 0x20`
  (`WITHIN_FOREST`).
- **4. Transitive?** `trustAttributes = 0x20` → `NON_TRANSITIVE (0x1)` bit **not** set → **transitive**.

### Trust T2

- **1. Domains joined:** `aldermont.local` and `trentham.local`.
- **2. Direction — perspective: `aldermont.local`** (the domain holding this object):
  - outbound component — does `aldermont` trust `trentham`? **yes**
  - inbound component — is `aldermont` trusted by `trentham`? **yes**
  - `trustDirection = 3` → **bidirectional** (both components present on this one object).
- **3. Type:** `trustType = 2` → **uplevel Windows (AD/Kerberos)**; `trustAttributes = 0x8`
  (`FOREST_TRANSITIVE`), i.e. a forest trust.
- **4. Transitive?** `trustAttributes = 0x8` → `NON_TRANSITIVE (0x1)` bit **not** set → **transitive**
  (the `FOREST_TRANSITIVE` bit itself names the transitive class).

| Trust | Domains joined | Direction (perspective) | Type | Transitive? |
|-------|----------------|-------------------------|------|-------------|
| **T1** | `corp.aldermont.local` — `aldermont.local` | bidirectional, from `corp` (`trustDirection=3`) | uplevel AD (`trustType=2`, `0x20 WITHIN_FOREST`) | yes (no `0x1` bit) |
| **T2** | `aldermont.local` — `trentham.local` | bidirectional, from `aldermont` (`trustDirection=3`) | uplevel AD (`trustType=2`, `0x8 FOREST_TRANSITIVE`) | yes (no `0x1` bit) |

---

> The sections below are **not** structural trust fields. They do not add to, qualify, or
> re-derive anything in Part A. They are recorded here only because the task asks for them.

## Part B — (not a trust field) what an identity crossing is subject to

Determined by trust kind, not stored on the trust object:

- **T1** (within-forest, `0x20`): **no SID filtering** — SIDHistory / `ExtraSids` honoured.
- **T2** (forest trust, `0x8`): **SID filtering ON** — SIDs foreign to the trusted forest, and
  any SID with RID < 1000, are stripped from the inter-realm PAC. This filtering is the one
  administratively-settable control in the map (relaxable via `netdom /enablesidhistory`); on
  this estate it is set to filter. Proven in the FLAG_FILTER task, not claimed as a crossing here.

## Part C — (not a trust field) reachable direction, access not assumed

"Reachable" here means only the direction the trust lets an authentication request travel (per
Part A); it asserts **no** access to any resource — that is governed by ACLs this map does not
enumerate.

- **T1:** authentication may traverse in the direction Part A records; no SID filtering strips
  authority minted inside the forest. Whether any identity can read any object is an ACL
  question and is **not** claimed here.
- **T2:** authentication may traverse in the direction Part A records, but SID filtering removes
  foreign / RID<1000 SIDs, so injected authority does not traverse — the trust **alone** grants
  no access into `trentham.local`. Consistent with that, an unprivileged bind by the foothold to
  TRENTHAM-DC is **refused** (`AcceptSecurityContext error, data 52e`).

### Boundary summary
The **domain** is not the security boundary — within `aldermont.local`, T1 carries authority
between child and root unfiltered. The **forest** is the boundary that holds — SID filtering on
T2 strips injected authority, so no `trentham.local` resource is reachable on the strength of the
trust itself.

> FLAG_TRUSTMAP — located at `\\ALDER-ROOT-DC\proof$\trustmap.txt`: `ALD{f05f5d1ffdcf5a577ce31756e43ff5ed}`
