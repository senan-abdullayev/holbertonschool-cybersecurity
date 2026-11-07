# 6 — The First Credential: Attack & Detection Report

**Prepared for:** Vanmark Group — Security / IT Operations
**Engagement:** Credential-free internal access assessment, `vanmark.local`
**Scope reached:** first low-privilege domain credential + reliable ADIDNS-based
positioning. No privilege escalation, relay, certificate or trust abuse (later phases).
**Casualties:** zero — no account was locked out.

---

## 1. The chain — what we did, in order, and why

We started on the segment with **no credential**. A flat internal network is not a
list of hosts to scan; it is a room of machines asking each other questions, and the
first job was to be positioned to hear them.

1. **Listen before acting.** Ran Responder in analyse mode first to confirm the
   segment was genuinely emitting name-resolution fallback (LLMNR/NBT-NS/mDNS) before
   answering anything. No scanning — a sweep announces you and buys nothing.
2. **Poison and capture.** Answered those broadcasts. Over a jittered 2–3 minute
   cadence two identities authenticated to us and we captured their NetNTLMv2:
   - `VANMARK\t.okonkwo` — via a stale lookup for `FILESRV-01`
   - `VANMARK\svc-backup` — via a lookup for `BACKUPSRV`
3. **The triage call (the decision that matters).** We cracked **`t.okonkwo`** and
   deliberately **left `svc-backup` alone**. A captured NetNTLMv2 proves only that an
   authentication happened — never that the password is weak. What told them apart was
   **account type, read straight off the name**: `svc-backup` is a *service account*
   (`svc-` prefix) — in a managed domain these carry long machine-generated secrets and
   are effectively uncrackable; spending cracking time there is the mistake the exercise
   is built to catch. `t.okonkwo` is a *human user* whose password follows a
   remember-it pattern. We confirmed the economics: a straight `rockyou` run exhausted
   against both (neither is a leaked-list password), so the decision was not "try and
   see" but "reason first."
4. **Crack by reasoning, not brute force.** `t.okonkwo` fell to a small, company-
   context wordlist + rules (`hashcat -m 5600`, `Word + year + symbol`), recovering
   **`Vanmark2026!`**. We then **authenticated** as `t.okonkwo` to the DC to prove the
   credential was real, not just a cracked string.
5. **Read the real policy.** With the credential we read the domain's *actual*
   lockout policy — **threshold 5, observation/reset window 30 minutes** — not the
   Windows default. This number, not an assumption, governed the next step.
6. **Spray, with discipline.** One likely password across the whole user list, **one
   attempt per account**, well under the threshold. The shared forced-reset password
   was reasoned — the *current season* + year + symbol — to **`Autumn2026!`**. It
   authenticated five accounts (`r.delacroix, m.arslan, s.ferreira, k.nowak, d.abioye`)
   with **zero lockouts**.
7. **Stop racing — own the answer.** Everything so far arrived because we replied
   first; that is luck, not a position. Using the credential, we exercised the default
   right of an authenticated user to **write a DNS record** into the AD zone. The victim
   `g.petrov` repeatedly queried `reports.vanmark.local` — a DNS-first name that returns
   NXDOMAIN and therefore never falls back to broadcast, so it could not be captured by
   poisoning. We injected a **single targeted A record** `reports.vanmark.local →
   10.10.0.2`, and on its next run `g.petrov` resolved to us and authenticated — a
   capture (`cifs/reports.vanmark.local`) that was **impossible without the record**.
8. **Revert.** Removed the record; the zone is back as we found it (§6).

---

## 2. What the credential bought

An ordinary low-privilege domain account is not "nothing" — it is the exact position
every assumed-breach engagement is handed for free. Inside `vanmark.local`, `t.okonkwo`
can now:

- **Enumerate the entire directory** over authenticated LDAP — every user, group,
  computer, OU, group membership, and account attribute (description fields, SPNs,
  `userAccountControl` flags). This is the raw material for BloodHound-style attack-path
  mapping.
- **Read the real security posture** — the domain password and lockout policy, trust
  relationships, and GPOs.
- **Read everything in SYSVOL / NETLOGON** — logon scripts, mapped-drive definitions,
  GPP files — a classic source of further hostnames, share paths, and (historically)
  embedded secrets.
- **Access authenticated SMB** — list and read any share whose ACL permits domain
  users (here, the `proofs$` policy share).
- **Hunt for the next step** — identify Kerberoastable service accounts (SPN set) and
  AS-REP-roastable users (pre-auth disabled) for offline attack, entirely as a normal
  user.
- **Write to AD-integrated DNS** — create records in the zone (the ADIDNS primitive we
  used), turning opportunistic capture into reliable, on-demand positioning.

In short: from one low-privilege password, an attacker gains **full read visibility of
the directory and a foothold to position traffic at will.** That is what you are
handing an adversary the moment any single staff password is guessed.

---

## 3. Detection — how you would have caught us

Every technique leaves a mark. Where it does not, the *absence* is itself evidence.

| # | Technique | What recorded it (specific) |
|---|-----------|------------------------------|
| 1 | **LLMNR/NBT-NS/mDNS poisoning** | Not a DC event — the auth landed on us, off your DC. The mark is **on the wire**: LLMNR (UDP 5355) and NBT-NS (UDP 137) *responses* originating from a host that is **not the authoritative owner** of the queried name. A decoy/canary hostname that should never resolve is the cleanest tripwire — any answer to it is an attacker. Detect with a network sensor (Zeek) or an LLMNR honeypot (Respounder). |
| 2 | **Offline NetNTLMv2 crack** | **Nothing.** Offline cracking is silent — no log, anywhere. This is the point: you cannot detect the crack, only the **capture** (row 1) and the **use** (row 3). Treat any credential as compromised from the moment its hash leaves the wire. |
| 3 | **Authentication with the recovered/sprayed credential** | DC Security log **4624** (successful logon), **Logon Type 3** (network), **Source Network Address = 10.10.0.2**, an unfamiliar workstation name, off-hours. `t.okonkwo` and five sprayed accounts logging on from a host that is not their workstation is the anomaly. |
| 4 | **Password spray** | DC Security log **4625** (failed logon) with a distinct **shape**: *many different* `Target User Name` values, **one** `Source Network Address` / `Workstation Name`, **exactly one** failure per account, all clustered within seconds, Sub Status **`0xC000006A`** (bad password) for valid users. The signature is breadth, not depth — N accounts × 1 attempt from 1 source, versus a brute force's 1 account × N attempts. |
| 5 | **ADIDNS record injection** | **Directory Service 5137** (object created) for a new **`dnsNode`** object named `reports` in the `DomainDnsZones` partition, **created by `t.okonkwo`** — a *user* account writing a DNS record, not a DHCP/DNS service account, is the giveaway. Corroborated by DNS-Server dynamic-update audit events. Field that gives it away: the **creator SID** on the record. |

**What we deliberately did *not* generate — and why their absence is evidence:**

- **No 4740 (account lockout) — count is exactly 0.** A naive spray trips at least one;
  ours tripped none. The clean 4740 ledger is the proof the spray was measured against
  your real threshold and window, not guessed.
- **No per-account failure bursts.** You will not find 5+ consecutive 4625s against any
  single account — the hallmark of brute force — because the spray was one-and-done per
  account.
- **No vulnerability-scan or port-sweep noise.** We never scanned; there is no mass
  connection fan-out to find. Working to a standard leaves a quieter record on purpose.

---

## 4. Mitigation — one control per technique that removes the path

Four techniques, four controls. Each **kills** the step, rather than merely slowing it.

| Technique | Control that removes the path |
|-----------|-------------------------------|
| **1. Name-resolution poisoning** | **Disable the fallback protocols fleet-wide.** GPO *"Turn off multicast name resolution"* (kills LLMNR) **and** disable NetBIOS over TCP/IP via DHCP option 001 / interface config (kills NBT-NS); disable mDNS where not needed. With no broadcast fallback there is **nothing to answer** — step 2 of our chain cannot occur. |
| **2. NetNTLMv2 crack economics** | **Make the captured hash worthless.** Move service accounts to **gMSA** (120-char auto-rotated secrets — `svc-backup`'s hash becomes uncrackable) and enforce a **long passphrase policy + banned-pattern list** for users so no captured hash is feasibly crackable. (Strongest form: *Restrict NTLM* / Kerberos-only removes the capturable material entirely.) This directly defeats step 4. |
| **3. Password spray** | **Require MFA for authentication.** A guessed password alone no longer grants access, so a sprayed credential is insufficient — step 6 produces no usable logon. Pair with **AD Password Protection** (banned list incl. `Season+Year+symbol`) so the shared seasonal password can never exist in the first place. |
| **4. ADIDNS injection** | **Revoke the default DNS write right.** Remove *"Create all child objects"* for **Authenticated Users** on the AD-integrated zone ACL (and require tightly-scoped secure dynamic updates). A low-privilege account can then no longer create a record — step 7 is blocked at the write. |

---

## 5. What the first credential is worth — the summary line

Everything above followed from **one** staff password. The lesson for Vanmark is that
the boundary that actually matters is the *first* credential: the controls in §4 are
cheap relative to what a single guessed password concedes (§2). Harden name resolution
and authentication, and the entire chain in §1 loses its first rung.

---

## 6. Closeout

- **Lockout count: 0.** The DC's committed `4740` tally for this engagement reads **0**;
  the exported Security log corroborates (no lockout events). Spray discipline held.
- **Injected record removed.** `reports.vanmark.local` (A → 10.10.0.2) was deleted after
  the demonstrating capture. Verified: `nslookup reports.vanmark.local 10.10.0.10` now
  returns **NXDOMAIN**, matching the pre-engagement state. No other records were created
  or modified; no wildcard was ever written.
- **Zone and accounts as found.** No passwords were changed, no accounts disabled, no
  persistence left behind. The environment is in the state we were handed it.

*Record of change (for your verification):*
`add  dnsNode "reports"  A 10.10.0.2  in DomainDnsZones\vanmark.local  —  then  remove.`
