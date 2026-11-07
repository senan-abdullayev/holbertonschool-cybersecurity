# 0 — The Plan, and the Line You Do Not Cross

## The route, in order, and when I abandon it

I do not treat this segment as a list of hosts to scan. It is a room of machines
asking each other questions, and my first job is to be positioned to hear them.
My goal is bounded — one working credential — in a fixed order, observation
before action:

1. **Orient and listen.** Watch which identities fall back to LLMNR/NBT-NS/mDNS
   and what names they chase; answer nothing until I understand who is asking.
2. **Capture.** Answer those broadcasts to collect the authentications they
   carry, across several windows to catch the full cadence, not one packet.
3. **Triage, then crack.** Attack only the identity worth it (below), with one
   bounded run of a targeted wordlist.
4. **Confirm.** Authenticate with any recovered secret to prove it is a real
   credential, not merely a hash.

My abandonment rule is evidence-based, not a stopwatch: once I have observed the
full cadence and collected every identity on offer, if my one bounded crack
returns nothing the route has failed — then I pivot to policy-aware user
enumeration and one lockout-safe spray.

## What I will actually attack

Not everything I collect. A captured authentication proves only that a login
happened — never that the password is weak. Two identities surface: one
effectively uncrackable decoy, one crackable by reasoning. I judge whose account
each is and whether a targeted wordlist plausibly contains it, attack it, and
leave the decoy alone.

## The line

Zero lockouts. I will not push any Vanmark account past its lockout threshold. I
find where it truly sits by reading the domain's real lockout policy
pre-authentication — the actual threshold and observation window, not the
default. My spray is one guess per account per window, strictly under the
threshold. If I cannot read the real policy, I do not spray at all; I stay on
observation until I can. This is the paragraph I am held to: my committed lockout
tally must read exactly 0.

## What the DC will have on me by day's end

Before I act it holds only a DHCP lease. By evening its logs should show the
name-resolution answers I gave, failed logons from one low-and-slow spray, zero
lockouts, and one DNS dynamic-update record from my targeted injection — never a
wildcard.
