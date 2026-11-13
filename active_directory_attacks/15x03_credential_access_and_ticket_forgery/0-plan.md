# 0-plan.md — The Plan, Before You Hold Everything

## Where Kessler's credential material lives (established before any access attempt)

Before taking anything I build a location map, separated three ways — **account context**, **replication boundary**, **protection condition** — so I know where each secret resides and under what protection before touching it:

- **Account contexts are distinct principals, not "I am admin."** User accounts (incl. `g.hale`), the co-located **service account** (→ silver), the **machine account** (DC$), and the **`krbtgt`** domain key each have their own store. Holding Domain-Admin rights is not the same as holding `krbtgt`.
- **In memory (LSASS):** only principals with a **live logon session** — machine/service material and currently-logged-on users. `krbtgt` has **no logon session** (the KDC uses it as stored key material; it never authenticates), so it is *structurally* absent here, not merely "not found."
- **At rest in the directory:** every secret, `krbtgt` included, lives in **`NTDS.dit`**, encrypted under the SYSTEM-hive **boot key**. Two routes with different boundaries: **replication** (DRS/DCSync — asks the DC, bounded by replication rights, leaves a 4662) and **the file** (`NTDS.dit` + SYSTEM hive parsed offline — bounded by disk access, no directory-service event).
- **DPAPI:** per-user masterkeys protect user secrets and are recoverable through the **domain DPAPI backup key** on the DC.

**Proving a route is closed — by corroboration, not one non-result.** The memory route to the domain key is closed *by design*; I establish that with three agreeing observations, not a single empty dump: (1) no enumerable `krbtgt` logon session on the host; (2) `krbtgt` absent from LSASS secrets across a full dump; (3) consistent with the architectural fact that the KDC never logs `krbtgt` on. A route is only **"done badly"** — retried, never declared closed — when the failure is operational (auth error, clock skew, name-resolution miss, access denied), which is fixable and says nothing about where the secret lives. Only once the memory route is *established* closed do I move to the directory.

## Choosing a capability per objective

**Selection rule: the least expansive capability that proves the objective** — fewest accounts/systems touched, shortest lifetime, lowest revocation burden, least network contact, least visibility. I score every objective on the seven axes below together and take the lowest row that satisfies it, escalating only when it genuinely needs more authority.

| Capability | Identity | Authority | Systems | Lifetime | Revocation | Network | Visibility |
|---|---|---|---|---|---|---|---|
| Silver | 1 service key | that SPN | 1 host | ticket | reset svc pw | **none (no KDC)** | invisible |
| DCSync | repl right | chosen accts | DC | momentary | rotate accts | DRS/LDAP | one 4662 |
| Offline NTDS | file+boot key | whole dir | DC disk | n/a | rotate all | none | no DS event |
| Golden (AES) | krbtgt key | domain | all hosts | long | 2× krbtgt reset | none (forged) | loud |
| Diamond | krbtgt+TGT | domain | all hosts | long | krbtgt reset | 1 AS-REQ | low |

I default to the top row that proves the objective; "works everywhere" (golden RC4) is rejected whenever a narrower row suffices.

## Recording what I build — a revocation-ready inventory

Every artefact — credential, key, ticket, or derived material — gets one complete record, all nine fields filled at creation time, so Kessler can invalidate each item without hunting (values below are the template filled per real artefact at forge/extract time):

| Artefact (type) | Identifier | Created | Expiry | Source / key version | Scope/target | Storage | Use | Invalidate action |
|---|---|---|---|---|---|---|---|---|
| Extracted secrets (dump) | sAMAccountName + RID; NT/AES256 hash | dump time | none — valid until rotated | from `NTDS.dit` + SYSTEM boot key | those accounts | `evidence/ntds/secrets.dump` | read offline | rotate each account; delete dump |
| krbtgt key | `krbtgt` acct + kvno N; AES256 hash | extract time | none — until reset | DCSync / offline NTDS | domain-wide | `evidence/krbtgt.txt` | seeds golden/diamond | **double** krbtgt reset (2 rotations >10h apart) |
| DPAPI domain backup key | backup-key GUID + version | recover time | none — until re-seeded | `backupkeys` via domain backup key | all domain DPAPI masterkeys | `evidence/dpapi/backupkey.pvk` | derive masterkeys | re-seed domain backup key; delete plaintext |
| DPAPI masterkey(s) | masterkey GUID per user | decrypt time | none — until re-protected | backup key above | that user's secrets | `evidence/dpapi/masterkeys/` | decrypt FLAG_DPAPI blob | force masterkey re-protection; delete plaintext |
| Silver ticket | target SPN + service acct; AES key | forge time | forge + ticket lifetime (~10h) | service AES256 hash | 1 service / 1 host | `evidence/silver.ccache` | access service, no KDC request | reset service account pw; delete file |
| Golden ticket | impersonated user + domain SID; krbtgt kvno | forge time | forge + lifetime | krbtgt AES256 | domain-wide | `evidence/golden.ccache` | domain-wide auth | double krbtgt reset; delete file |
| Diamond ticket | base user + real TGT id; krbtgt kvno | forge time | inherited from real TGT | krbtgt AES256 | domain-wide | `evidence/diamond.kirbi` | domain auth, legitimate-looking | krbtgt reset; delete file |
| Foothold TGT | `g.hale` UPN; TGT id | getTGT time | +10h (renewable) | g.hale AES/NT key | g.hale's rights | `evidence/g.hale.ccache` | DCSync, admin on DC | reset `g.hale` password; delete ccache |

Persistence is only real if each record names exactly what to rotate, reset, or delete.

## What the DC will have recorded

I expect 4662 for DCSync; **nothing** for the silver forge or its use (no 4768/4769); 4624/4672 on ticket use; the offline read leaving no directory-service event. Predicting the silence tests understanding, not commands.
