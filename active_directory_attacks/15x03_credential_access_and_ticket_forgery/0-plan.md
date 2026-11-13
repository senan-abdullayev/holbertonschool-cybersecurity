# 0-plan.md — The Plan, Before You Hold Everything

## Locating the material before taking it

I map where Kessler's key material lives before grabbing it, and probe the **memory route first on purpose** — a credential dump returns live sessions and machine/service secrets but **no `krbtgt`**. That empty result is the signal: the domain master key never logs on, so it is never in LSASS. A route is "closed" when the right technique returns a well-formed answer lacking the secret, as distinct from "done badly" — an auth error, `KRB_AP_ERR_SKEW`, a name-resolution miss, access denied — which is fixable, not conclusive. Only after the memory wall do I turn to the directory, reachable two ways: replication (DCSync) and the file on disk (`NTDS.dit` + SYSTEM boot key, offline).

## Choosing a capability per objective

I pick by **blast radius and detectability**, not "works everywhere." DCSync for one account quietly, accepting the 4662 trace. Offline `NTDS.dit` for everything without touching the directory service. Silver for one service with **no KDC contact**. Golden (AES, never RC4) for domain-wide reach, accepting the loud case. Diamond when I want a forgery that rides a real TGT. "The one that works everywhere" is golden RC4 — it forfeits the professional half of the grade.

## Recording what I build — a revocation-ready inventory

Each artifact gets one record, six fields, so Kessler can invalidate it without hunting: **(1) identifier** — type + name (principal/SPN, account, key, file); **(2) lifecycle** — created-at, lifetime/expiry, algorithm (AES); **(3) scope/target** — what it authenticates to and its blast radius; **(4) storage** — exact path of the `.kirbi`/`.ccache`/dump; **(5) use** — where I authenticated with it; **(6) invalidate action** — the explicit per-item undo:

- **Extracted secrets (NTDS dump, service/machine keys)** → rotate those accounts; delete the dump.
- **krbtgt key** → **double** krbtgt reset (two rotations, >10h apart).
- **DPAPI backup key + masterkeys** → re-seed the domain DPAPI backup key; force re-protection; delete recovered plaintext.
- **Silver ticket** → reset the target service account's password; delete the file.
- **Golden ticket** → double krbtgt reset (as the key).
- **Diamond ticket** → krbtgt reset invalidates it; delete the output.
- **Foothold use** → reset `g.hale` and any touched account; host reset on the DC.

Persistence is only real if each record names exactly what to rotate, reset, or delete.

## What the DC will have recorded

I expect: 4662 for DCSync; **nothing** for the silver forge or its use (no 4768/4769); 4624/4672 on ticket use; the offline file-read leaving no directory-service event. Predicting the silence tests whether I understand the technique, not just the command.
