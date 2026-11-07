<!-- SPDX-License-Identifier: Apache-2.0 -->
# sayfirst and the EU AI Act: Articles 12 and 14

> **Two numberings on one page.** "AI Act Article N" is an article of
> Regulation (EU) 2024/1689. "Constitution article N" is an article of this
> repository's [`CONSTITUTION.md`](../CONSTITUTION.md). The two are unrelated,
> and two pairs cross: **AI Act Article 12** (record-keeping) is served by what
> **constitution article 10** (evidence) governs, and **AI Act Article 14**
> (human oversight) by what **constitution article 12** (approvals) governs.

## What this page is, and what it is not

sayfirst provides a mechanism, never a conformity (constitution articles 2
and 11). Nothing on this page makes an AI system, a deployment or an
organisation compliant with the AI Act. The open project ships no compliance
package, disclosure register or regulatory workflow (constitution article 10),
and regulatory reporting belongs to products built on top of it (constitution
article 1). The obligations below fall on the providers and deployers of
high-risk AI systems. This page says which parts of AI Act Articles 12 and 14
the mechanism can **support** when it is part of such a system, how far, and
what stays with you. It is not legal advice.

sayfirst is not a sandbox. A governed program *calls* the boundary; a program
that does not call it is not governed, and nothing here stops it. Every row
below is about the effects a program puts to the control plane, and about no
others. Pair it with operating-system sandboxing for code you do not trust
(constitution article 2).

## Where the law stands (checked on 2026-11-07)

- Regulation (EU) 2024/1689, the Artificial Intelligence Act, was published in
  the Official Journal on 12 July 2024 and entered into force on 1 August 2024
  ([EUR-Lex](https://eur-lex.europa.eu/legal-content/EN/ALL/?uri=CELEX:32024R1689):
  "Date of effect: 01/08/2024; Entry into force Date pub. +20").
- Regulation (EU) 2026/1744, the Digital Omnibus on AI, was published on
  24 July 2026 and entered into force on 27 July 2026
  ([EUR-Lex](https://eur-lex.europa.eu/legal-content/EN/ALL/?uri=CELEX:32026R1744)).
  Its Article 1, point (40), replaced point (c) of AI Act Article 113: "Chapter
  III, Sections 1, 2, and 3, with the exception of Article 6(5), shall apply
  from: (i) 2 December 2027 as regards AI systems classified as high-risk
  pursuant to Article 6(2) and Annex III; and (ii) 2 August 2028 as regards AI
  systems classified as high-risk pursuant to Article 6(1) and Annex I"
  ([Official Journal text](https://eur-lex.europa.eu/eli/reg/2026/1744/oj)).
- AI Act Articles 12 and 14 sit in Chapter III, Section 2, and the provider and
  deployer obligations of Articles 16, 19 and 26 in Section 3. So both articles
  apply from **2 December 2027** to Annex III systems and from **2 August 2028**
  to Annex I systems.
- The Digital Omnibus did not change the wording of Articles 12, 14, 16, 19 or
  26. The quotations below are from the
  [Official Journal text of 2024/1689](https://eur-lex.europa.eu/eli/reg/2024/1689/oj),
  and match the consolidated version of 27 July 2026 that its
  [EUR-Lex page](https://eur-lex.europa.eu/legal-content/EN/ALL/?uri=CELEX:32024R1689)
  links to, which EUR-Lex publishes as a documentation tool with no legal
  effect.

## AI Act Article 12 — record-keeping

> 1. High-risk AI systems shall technically allow for the automatic recording
>    of events (logs) over the lifetime of the system.

Paragraph 2 asks the logs to enable the recording of events relevant for
identifying risk situations or a substantial modification, for post-market
monitoring, and for the deployer's monitoring under Article 26(5). Paragraph 3
sets minimum contents for the remote biometric identification systems of
Annex III, point 1(a).

| What AI Act Article 12 asks | What sayfirst supports | What stays with you |
|---|---|---|
| Automatic recording of events over the lifetime of the system (12(1)) | Every decision on a governed effect is written to a hash-chained evidence chain, kept per scope, without the program doing more than asking. A record the store cannot take under pressure becomes a declared gap, never a silent one (constitution article 10). Retention is indefinite in this version: nothing in the chains, the decision files or the policy archive expires, and there is no purge command ([`docs/deployment.md`](deployment.md)). | Deciding which effects are governed. An effect that never reaches the boundary is not recorded, and nothing the model computes is recorded. Backups of the evidence root. **Partial.** |
| Events relevant for traceability (12(2)) | Each decision names its capability, scope, principal, outcome, reason and time, and the policy version it was taken under; every policy version a decision names is archived byte for byte. `trace` follows one decision into the chain and `explain` gives the daemon's own reason and rule. | Which events are relevant to the system's risks is the provider's analysis. Arguments and content are not recorded by default (constitution article 11); capture is opt-in per capability, bounded and marked. **Partial.** |
| Minimum contents for Annex III, point 1(a) systems (12(3)) | None of the four points. Who approved or rejected a suspended effect is taken from the kernel-verified connection, but it is kept only on the approval record, which lives in memory, and not in any log; point (d) concerns the two-person verification of AI Act Article 14(5), which the open core does not offer. | Points (a) to (d). **Not supported.** |

**How far a reader can trust the record.** Article 12 does not use the word
integrity, but a log is worth what its store is worth, and sayfirst says what
its store is worth. A deployment of this version is graded **observability** —
the governed program can write or replace the evidence store, so the chain
detects accidental corruption only — or **unverified**, which claims nothing.
At neither grade is any claim of proof or of tamper detection made.
Constitution article 7 defines a third grade, evidence grade, and no
deployment of this version reaches it ([`SECURITY.md`](../SECURITY.md)).

**What a third party can check.** An exported bundle is checked offline with the
contract distribution alone, no daemon, and its verdict says what it could not
check: a range inside the daemon's open epoch reports coverage `unknown`, and a
decision a person granted re-derives as `unverifiable`, because a policy file
cannot re-derive a human act.

**Retention.** AI Act Articles 19(1) and 26(6) ask providers and deployers to
keep the logs "for a period appropriate to the intended purpose of the
high-risk AI system, of at least six months", to the extent the logs are under
their control. Nothing in sayfirst's chains, decision files or policy archive
expires, and this version has no purge command; a file removed by hand is
disclosed as absent in an export and never recreated
([`docs/deployment.md`](deployment.md)). Waits and the in-memory events sink
are not logs and are not kept.

## AI Act Article 14 — human oversight

> 1. High-risk AI systems shall be designed and developed in such a way,
>    including with appropriate human-machine interface tools, that they can be
>    effectively overseen by natural persons during the period in which they are
>    in use.

Paragraph 4 lists what the people assigned to oversight must be enabled to do,
among them "(d) to decide, in any particular situation, not to use the
high-risk AI system or to otherwise disregard, override or reverse the output
of the high-risk AI system" and "(e) to intervene in the operation of the
high-risk AI system or interrupt the system through a ‘stop’ button or a
similar procedure that allows the system to come to a halt in a safe state".
Paragraph 5 asks, for Annex III, point 1(a) systems, that an identification be
"separately verified and confirmed by at least two natural persons".

| What AI Act Article 14 asks | What sayfirst supports | What stays with you |
|---|---|---|
| Effective oversight by natural persons while the system is in use (14(1)) | A rule whose outcome is `suspend` makes a governed effect wait for a person before it happens. The policy is a file a person reads and edits, and the next decision is taken on the edited file, without a restart. | The oversight design of the AI system as a whole. sayfirst oversees the effects it is asked about, not the model. **Partial.** |
| Measures built in by the provider or implemented by the deployer (14(3)) | The control plane can be one such measure, built into a system by its provider, or implemented by a deployer where the provider identifies it as such a measure. | Identifying the measures, and their being commensurate with the risks. |
| Understanding capacities and limitations, automation bias, interpreting output (14(4)(a) to (c)) | `explain` gives the reason, rule and policy version behind one of the daemon's own decisions. | Everything about the model's capacities and output. **Not supported.** |
| Deciding not to use, disregard or override (14(4)(d)) | `approvals reject` ends a wait: the effect does not happen, and the same question is denied with the person's reason until the wait's deadline, and a restart forgets it. Changing a rule to `deny` refuses the effect from the next decision on. | Overriding or reversing the model's output itself. **Partial.** |
| Intervening, or interrupting through a stop button or similar (14(4)(e)) | A rule changed to `deny` applies from the next decision; a grant already delivered stops being honoured once the daemon next consults the changed policy; with the control plane stopped (`sayfirst-daemon down`), an effect that has not started does not start, and the program is told « could not ask » (exit `4`), never « denied ». Nothing reaches the evidence chain while the daemon is down. | An effect already allowed may continue within the lifetime it was given (constitution article 1). The program itself is not stopped, only its governed effects; bringing the system to a halt in a safe state is the system's design. **Partial.** |
| Verification by at least two natural persons (14(5)) | Not in the open core: one person approves or rejects (constitution article 12). Approval by two distinct, designated people arrives through the approval port, implemented by a product built on top. | All of it. **Not supported by the open core.** |

**Who the person is.** AI Act Article 26(2) asks deployers to "assign human
oversight to natural persons who have the necessary competence, training and
authority, as well as the necessary support". sayfirst holds no designation: every principal the socket admits
may resolve any wait, and "designated" means no more than admitted. The daemon
takes the person who acted from the connection — its kernel-verified principal,
never a member of the request. That person is on the approval record, which is
kept in memory for as long as the wait is and is lost at a restart; the
evidence chain and the decision files do not repeat it.
[`docs/deployment.md`](deployment.md) ("Who may resolve a suspended effect"
and "What a restart loses") says where the person is kept and for how long.

## In one paragraph

For the effects a program puts to it, sayfirst records automatically what was
asked and what was answered, keeps those records with no expiry, lets a third
party check the chain offline at the grade it states, and can make an effect
wait for one person, refuse it, or stop allowing it without a restart. That supports parts
of AI Act Articles 12 and 14, partially, for those effects. It does not record
or oversee the model, offers no two-person verification in the open core,
makes no claim of proof or of tamper detection, and makes nothing compliant.
