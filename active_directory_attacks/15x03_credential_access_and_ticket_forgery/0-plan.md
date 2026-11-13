# 0-plan.md — The Plan, Before You Hold Everything

## Locating the material before taking it

I start by mapping where Kessler's key material actually lives, not by grabbing it. On the DC I will enumerate the directory, the KDC, DNS, and the one co-located authenticable service, and I will probe the **memory route first on purpose** — a credential dump that returns live sessions and machine/service secrets but **no `krbtgt`**. That empty result is the signal, not a failure: the domain master key never logs on, so it is never in LSASS. A route is "closed" when the technique that should surface a secret returns a well-formed answer that does not contain it (memory has no `krbtgt`), as distinct from "done badly," which looks like an auth error, a skew/`KRB_AP_ERR_SKEW`, a name-resolution miss, or an access denied — fixable, not conclusive. Only after the memory wall do I turn to the directory, reachable two ways: replication (DCSync) and the file on disk (`NTDS.dit` + SYSTEM-hive boot key, offline).

## Choosing a capability per objective

For each objective I pick by **blast radius and detectability**, not by "works everywhere." Replication/DCSync when I want one account quietly but can accept the 4662 replication trace. Offline `NTDS.dit` when I want everything without touching the directory service. Silver when I only need one service and want **no KDC contact at all**. Golden (AES, never RC4) when I need domain-wide reach and will accept being the loud, powerful case. Diamond when I want a forged ticket that rides a real TGT and looks legitimate. "The one that works everywhere" is the golden RC4 answer — it forfeits the professional half of the grade.

## Recording what I build

Every forged artifact gets logged so Kessler can invalidate it: ticket class, principal/SPN, key material and algorithm (AES), timestamps/lifetimes, the account and keys it depends on, and where the output file lives. Persistence is only real if I can later point to exactly what must be rotated.

## What the DC will have recorded

I expect: 4662 for DCSync; **nothing** for the silver forge and its use (no 4768/4769); 4624/4672 on ticket use; and the offline file-read leaving no directory-service event. Predicting the silence is the test that I understand the technique, not just the command.
