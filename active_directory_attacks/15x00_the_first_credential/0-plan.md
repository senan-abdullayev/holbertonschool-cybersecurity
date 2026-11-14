# 0 — The Plan, and the Line You Do Not Cross

## The route from nothing to a first credential

I start with no account, so I do not treat `vanmark-lab` as a list of hosts to scan — I treat it as a room of machines asking each other questions, and my first job is to be positioned to hear them. I lease a DHCP address, confirm the DC at `10.10.0.10` passively (`arp-scan -l`, `nmap -sn`), and then **listen before I answer**: Responder in analyse-only mode first, to see which names fall back to LLMNR/NBT-NS/mDNS and on what cadence. Only once I know what is broadcasting do I answer, capturing NetNTLMv2 material from the identities that authenticate over the wire.

Approach one is poisoning-then-cracking. I abandon it for approach two — policy-aware spraying — the moment the captured material is not economically crackable (see triage), or when a recovered credential plus pre-auth enumeration (`nxc`/`kerbrute`, `--pass-pol`, `GetADUsers.py`) opens a cheaper path to a second account than cracking does. Spraying is not a fallback for failure; it is the next lead when the first stops paying.

## Deciding what is worth attacking

"Crack everything I collect" is a plan for running out of week. Two identities will surface, and they are not equal: one is an effectively uncrackable decoy, the other yields to a *reasoned, targeted* wordlist rather than a blind giant dictionary. I triage on expected cost before spending GPU time — who is this account, does its material fit a small keyspace I can justify (a bounded pattern), and what does cracking it buy me? A hash only proves an authentication happened; it does not prove the password is weak. If the economics don't close, I set it aside as a decoy and move to spraying.

## The limit I will not cross

**Zero lockouts.** I will not put more than one guess against any account per observation window. I establish where that line actually sits — not where I assume it sits — by reading the real policy from the domain itself (`--pass-pol`: threshold **and** observation window), never the Windows default. If I cannot read it, I do not spray on a guess; I keep listening, cracking, and enumerating until I can. An unknown threshold is an unacceptable threshold.

## What the DC will have recorded by day's end

Benign poisoning answers, a flurry of `4625` failed logons from one disciplined spray round, **zero** `4740` lockouts, one `4624` success per credential I prove, and a single targeted dynamic DNS-update event if I inject an ADIDNS record. No wildcard, nothing irreversible.
