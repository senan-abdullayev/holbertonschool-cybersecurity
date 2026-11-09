# 0-plan.md — Coercion and Relay: Plan Before the Playbook Fails

## What I establish before spending any authentication

Before I coerce anything or fire a single relay, I fingerprint posture on both
hosts with the foothold credential alone, in this order:

1. **Confirm the two hosts and services** — `nmap -sn 10.20.0.0/24`, then a
   focused service scan of `10.20.0.10` (CALDER-DC01) and `10.20.0.20`
   (SRV-LEGACY). Reachability is not viability; I only note what is listening.
2. **SMB signing per host** — `nxc smb <host>`, read the `signing` field.
   Signing *required* closes SMB-relay to that host. I expect the DC to require
   it and SRV-LEGACY to have it off.
3. **LDAP channel binding + EPA on the DC** — `nxc ldap` binding check. If
   enforced, an SMB-origin relay into LDAP is closed; only a WebDAV/HTTP-origin
   relay can satisfy the missing channel binding.
4. **WebClient (WebDAV) presence** — confirm the coercion victim (SRV-LEGACY)
   runs WebClient, since the HTTP-origin LDAP leg depends on it.

**What makes me call a target closed:** signing `required` in the `nxc` output
closes SMB relay to it; channel binding/EPA enforced closes the SMB-origin LDAP
relay. I record the observed field, not an assumption.

## When the first relay attempt fails

A failed relay is triage data, not an endpoint. I return to the posture map,
ask which modern default rejected it, and pivot the *origin* or the *target*
accordingly — e.g. if SMB-origin to LDAP is refused on channel binding, switch
to a WebDAV/HTTP origin. I never relay a victim back to itself, and I never
claim a relay against the hardened DC.

## The standard a finding must meet

A relay path enters the report only when I have confirmed the *identity or
position reached* at that hop — captured machine auth, code execution on
SRV-LEGACY, the RBCD attribute written, the S4U ticket impersonating the
privileged user. A command exiting 0 is not proof. If I believe a path exists
but cannot demonstrate the reached identity, I write it as an **unproven
hypothesis** with the specific evidence that is missing — never as a result.

## What the DC will have recorded

Before I begin, I expect the DC to end the engagement holding: my foothold
logons, the coercion-trigger RPC calls, the authentication the coerced host
sent, the machine account I stage (Powermad), and the
`msDS-AllowedToActOnBehalfOfOtherIdentity` write plus the S4U/TGS requests.
Those traces are the controls story — signing, EPA, channel binding, RPC
filters — my review answers will map back to.
