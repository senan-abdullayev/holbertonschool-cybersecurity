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

Every artifact gets one complete record — all six fields filled at creation time — so Kessler can invalidate each item without hunting:

| Artifact | Identifier | Lifecycle (created · expiry · source/version) | Scope/target | Storage | Use | Invalidate action |
|---|---|---|---|---|---|---|
| Extracted secrets | account name + RID; NT/AES hash | dumped-at · n/a · from `NTDS.dit`+SYSTEM | those accounts | `evidence/ntds/*.dump` | read offline | rotate each account; delete dump |
| krbtgt key | `krbtgt` + kvno + AES256 hash | extracted-at · n/a · DCSync/offline | domain-wide | `evidence/krbtgt.txt` | seeds golden/diamond | **double** krbtgt reset (>10h apart) |
| DPAPI backup key + masterkeys | backup-key GUID; masterkey GUIDs | recovered-at · n/a · domain backup key | all DPAPI secrets | `evidence/dpapi/` | decrypt FLAG_DPAPI | re-seed backup key; force re-protect; delete plaintext |
| Silver ticket | SPN + service acct; AES key used | forged-at · ticket lifetime · service AES hash | 1 service/host | `evidence/silver.ccache` | access service, no KDC | reset service account pw; delete file |
| Golden ticket | user + domain SID; krbtgt kvno | forged-at · lifetime · krbtgt AES256 | domain-wide | `evidence/golden.ccache` | domain-wide auth | double krbtgt reset; delete file |
| Diamond ticket | base user + real TGT; krbtgt kvno | forged-at · inherited lifetime · krbtgt AES256 | domain-wide | `evidence/diamond.kirbi` | domain auth, legit-looking | krbtgt reset; delete file |
| Foothold use | `g.hale` + any touched account | session start/end · n/a | per touched account | `evidence/notes.md` | DCSync, admin on DC | reset `g.hale` + touched accts; DC host reset |

Persistence is only real if each record names exactly what to rotate, reset, or delete.

## What the DC will have recorded

I expect 4662 for DCSync; **nothing** for the silver forge or its use (no 4768/4769); 4624/4672 on ticket use; the offline read leaving no directory-service event. Predicting the silence tests understanding, not commands.
