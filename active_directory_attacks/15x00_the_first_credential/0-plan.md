# 0 — The Plan, and the Line You Do Not Cross

## The route, in order, and when I abandon it

I start from the only thing I have: a seat on the segment. This is not a list of
hosts to scan — it is a room of machines asking each other questions, so my first
move is to hear them. I run Responder in analyse mode first to
confirm who is broadcasting LLMNR/NBT-NS/mDNS fallback and what names they seek,
then I answer those queries to capture NetNTLMv2 material over a few poisoning
cycles. Poisoning leads because it costs the target nothing and risks no account.
From the captured identities I crack the one worth cracking and authenticate with
it. I abandon poisoning-first for the enumeration-and-spray path only if capture
yields nothing crackable within a reasoned cracking budget — i.e. both captured
hashes resist a targeted wordlist. Then I pivot to policy-aware user enumeration
and a single disciplined spray.

## What I will actually attack

Not everything I collect. A captured NetNTLMv2 hash proves only that an
authentication happened — never that the password is weak. Two identities will
surface: one effectively uncrackable decoy, one crackable by reasoning. Before
spending cracking time I triage: whose account is it, and does a targeted,
company- and context-derived wordlist plausibly contain it? I crack the reasoned
candidate and leave the decoy alone rather than burn the week on it.

## The line

Zero lockouts. I will not push any Vanmark account past its lockout threshold. I
find where that line truly sits by reading the real domain policy — `--pass-pol`
via NetExec/kerbrute — for the actual threshold and observation window, not the
Windows default I might assume. My spray is one guess per account per window,
staying strictly under the threshold. If I cannot establish the real policy, I do
not spray at all; I stay on poisoning until I can read it. This is the paragraph
I am held to: my committed 4740 tally must read exactly 0.

## What the DC will have on me by day's end

Before I act it has only a DHCP lease. By evening I expect: LLMNR/NBT-NS answers
on the wire, a burst of 4625 failed logons from one low-and-slow spray, zero 4740
lockout events, and a single DNS dynamic-update record from my one targeted
ADIDNS injection — never a wildcard.
