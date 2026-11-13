# 0-plan.md — The Plan, Before You Hold Everything

## Locating the material before taking it

I map where key material lives before grabbing it, probing the **memory route first** — a dump returns machine/service secrets but **no `krbtgt`**: the domain master key never logs on, so it is never in LSASS. That empty result is the signal, not failure. A route is "closed" when the right technique returns a well-formed answer lacking the secret — not "done badly" (auth error, skew, name miss, access denied), which is fixable. Only then the directory: DCSync, or `NTDS.dit` + SYSTEM boot key offline.

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
