# 0 — The Plan, and the Line You Do Not Cross

## The route, in order, and when I abandon it

My goal is bounded: from a no-credential start, obtain one working domain
credential — nothing more. I work in a fixed order, cheapest and least intrusive
step first:

1. Locate the DC — `arp-scan -l` / `nmap -sn 10.10.0.0/24` — without touching any
   account.
2. Listen — run Responder in analyse mode to see which hosts fall back to
   LLMNR/NBT-NS/mDNS and what names they seek.
3. Capture — answer those queries to collect NetNTLMv2 authentications over
   successive poisoning cycles.
4. Crack — run a targeted wordlist against only the one identity triage says is
   worth it.
5. Authenticate with the recovered password to prove the first credential.

My abandonment rule is concrete: if after ~60 minutes of capture I
hold no NetNTLMv2 hash that a curated, context-derived wordlist (a few hundred
thousand candidates in one cracking session, not a giant dictionary) recovers, I
declare the capture path exhausted and move to the secondary path — policy-aware
user enumeration, then one lockout-safe spray.

## What I will actually attack

Not everything I collect. A captured NetNTLMv2 hash proves only that an
authentication happened — never that the password is weak. Two identities will
surface: one effectively uncrackable decoy, one crackable by reasoning. I triage
whose account it is and whether a targeted wordlist plausibly contains it, crack
that one, and leave the decoy alone.

## The line

Zero lockouts. I will not push any Vanmark account past its lockout threshold. I
find where that line truly sits by reading the real domain policy — `--pass-pol`
via NetExec/kerbrute — for the actual threshold and observation window, not the
Windows default I might assume. My spray is one guess per account per window,
strictly under the threshold. If I cannot read the real policy, I do not spray at
all; I stay on poisoning until I can. This is the paragraph I am held to: my
committed 4740 tally must read exactly 0.

## What the DC will have on me by day's end

Before I act it holds only a DHCP lease. By evening I expect: LLMNR/NBT-NS
answers, a burst of 4625 failed logons from one low-and-slow spray,
zero 4740 lockouts, and a single DNS dynamic-update record from my one targeted
ADIDNS injection — never a wildcard.
