# 0-plan.md — Coercion and Relay: Plan Before the Playbook Fails

## What I establish before spending any authentication

Before I coerce or relay anything, I fingerprint posture on both hosts with the
foothold credential alone:

1. **Confirm hosts/services** — `nmap -sn 10.20.0.0/24`, then a focused scan of
   `.10` (CALDER-DC01) and `.20` (SRV-LEGACY). Reachability is not viability.
2. **SMB signing per host** — `nxc smb`; signing *required* closes SMB-relay to
   that host. I expect it required on the DC, off on SRV-LEGACY.
3. **LDAP channel binding + EPA on the DC** — `nxc ldap` binding check. If
   enforced, an SMB-origin LDAP relay is closed; only a WebDAV/HTTP origin
   satisfies the missing channel binding.
4. **WebClient (WebDAV)** — confirm the victim SRV-LEGACY runs it, since the
   HTTP-origin LDAP leg depends on it.

**What makes me call a target closed** is the observed field, not an assumption:
`signing: required` closes SMB relay; channel binding/EPA enforced closes the
SMB-origin LDAP relay.

## When the first relay attempt fails

A failed relay is triage data, not an endpoint. I return to the posture map,
ask which modern default rejected it, and pivot the *origin* or *target* — if
SMB-origin to LDAP is refused on channel binding, I switch to a WebDAV/HTTP
origin. I never relay a victim to itself, nor claim a relay on the DC.

## The standard a finding must meet

A relay path enters the report only when I confirm the *identity or position
reached* at that hop — captured machine auth, exec on SRV-LEGACY, the RBCD write,
the S4U ticket for the privileged user. A command exiting 0 is not proof. If I
believe a path exists but cannot demonstrate the reached identity, I write it as
an **unproven hypothesis** with the missing evidence named — not a result.

## What the DC will have recorded

I separate DC telemetry from what lives elsewhere: the coercion trigger
(MS-EFSRPC/RPRN/DFSNM RPC call) hits the victim SRV-LEGACY and the captured
authentication lands on my ntlmrelayx host — neither is a DC record. On
CALDER-DC01, each record carries *account, source, destination, logon/auth type,
object, operation, timestamp*:

- **Logon (4624/4625):** the relayed LDAP auth — coerced machine account, from
  my relay host IP, NTLM, logon type 3.
- **Computer account created (4741):** Powermad's `New-MachineAccount`, caller
  `a.foster`.
- **Directory object modified (5136):** the
  `msDS-AllowedToActOnBehalfOfOtherIdentity` write on the victim object (value
  added).
- **Kerberos TGS (4769) / S4U:** the S4U2Self/S4U2Proxy requests, impersonating
  the privileged user.

These DC records are the controls story my review answers map back to —
signing, EPA, channel binding, RPC filters.
