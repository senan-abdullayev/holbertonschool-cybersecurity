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

Each artifact gets one record, six fields, so Kessler can invalidate it without hunting: **(1) identifier** (type + name); **(2) lifecycle** (created-at, lifetime/expiry, algorithm — AES); **(3) scope/target** (what it authenticates to, blast radius); **(4) storage** (`.kirbi`/`.ccache`/dump path); **(5) use** (where I authenticated); **(6) invalidate action** (explicit per-item undo):

- **Extracted secrets (NTDS dump, service/machine keys)** → rotate those accounts; delete the dump.
- **krbtgt key** → **double** krbtgt reset (>10h apart).
- **DPAPI backup key + masterkeys** → re-seed the backup key; force re-protection; delete plaintext.
- **Silver ticket** → reset the service account's password; delete the file.
- **Golden ticket** → double krbtgt reset (as the key).
- **Diamond ticket** → krbtgt reset invalidates it; delete the output.
- **Foothold use** → reset `g.hale` and any touched account; host reset on the DC.

Persistence is only real if each record names exactly what to rotate, reset, or delete.

## What the DC will have recorded

I expect 4662 for DCSync; **nothing** for the silver forge or its use (no 4768/4769); 4624/4672 on ticket use; the offline read leaving no directory-service event. Predicting the silence tests understanding, not commands.
