<!-- SPDX-License-Identifier: Apache-2.0 -->
# Recipe `sayfirst/policy-evaluation/v1`

This is the normative text of the recipe named by `evaluation_recipe` on a
decision record and on an effect entry. The vectors beside it, in
`_contracts/domain/policy-evaluation-v1.json`, pin examples; this text defines
the remaining inputs. The identifier never changes meaning: a semantic change
mints a new identifier, and a record keeps naming the one it was taken under.

Two implementations exist and one fixture arbiter holds them apart (article
13): the control plane's live evaluator, which decides, and the contract
distribution's retrospective evaluator, which re-derives a decision already
taken and recorded. The retrospective one is a historical audit only; it
never authorises an effect. It consumes recorded inputs and archived policy
bytes, performs no input or output, reaches no daemon, holds no state, and
cannot mint a decision, an approval or a grant (article 1).

## Inputs

- the exact bytes of the policy version the record names;
- the recorded `scope`, `capability`, `principal_references` and
  `arguments_digest`;
- the recorded triple `(outcome, reason, rule_id)`.

The recipe checks the triple on recorded inputs. It does not check live
admission, grant lifetime eligibility, truthful identity or actual arguments.

## Rules

1. Decode the bytes as UTF-8 and parse them as TOML 1.0. Malformed bytes,
   duplicate keys or invalid shapes are `policy_unparseable`. The root keys are
   only `format`, `revision` and `rule`. `format` is the integer 1, never a
   boolean. `revision` has only `reason`, a non-empty string of at most 512
   characters without C0 or C1 control characters. A missing `rule` means an
   empty array; otherwise it is an array of tables.
2. Each rule has the required members `id`, `capability`, `principals`,
   `outcome` and `reason`, the optional members `scope`, `arguments_digest`,
   `grant_lifetime_seconds` and `review_deadline_seconds`, and no other. An id
   matches `^[a-z0-9][a-z0-9._-]{0,63}$` and is unique. A capability matches
   `^[a-z][a-z0-9]*(\.[a-z][a-z0-9]*)*$`. A scope defaults to `local` and
   matches `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`. A rule reason has the
   revision reason's bounds. Principals are a non-empty array of references:
   exactly one colon, a kind of `user` or `group`, a non-empty name of at most
   256 Unicode characters without C0 or C1 control characters; ordinary
   whitespace is accepted. Outcome is exactly `allow`, `deny` or `suspend`. A
   digest, when present, matches `^sha256:[0-9a-f]{64}$`. A lifetime, when
   present, is a positive non-boolean integer on an `allow` rule. A review
   deadline, when present, is a non-boolean integer from 1 to 86400 on a
   `suspend` rule; it bounds the wait, is not read by rules 3 or 4, and does
   not enter the triple. The deployment-configured upper bound on the lifetime
   is deliberately not reproduced: it affects live acceptance of a policy, not
   the triple this recipe checks. A member that no rule reads may be added to
   this list by naming it here, with a vector that carries it re-deriving as
   before and one that misplaces it re-deriving unparseable; a member any rule
   reads mints a new identifier. No Unicode normalisation, case folding,
   wildcard or inferred membership is applied.
3. A rule applies if and only if its capability and scope exactly equal the
   recorded ones, at least one of its principals is among the recorded
   references, and its pinned digest, when it has one, exactly equals the
   recorded digest. A null recorded digest never satisfies a pin.
4. No applying rule yields `(deny, policy_absent, null)`. Otherwise take the
   strictest outcome, `deny` before `suspend` before `allow`, then the first
   applying rule with that outcome in file order. Yield its id and,
   respectively, `policy_denies`, `policy_requires_review` or
   `policy_allows`. The administrator's reason text is never the returned
   reason.
5. The recipe's own reason vocabulary is exactly `policy_allows`,
   `policy_denies`, `policy_absent` and `policy_requires_review`. The published
   `reason` enumeration is wider: `capability_unknown` is answered before any
   policy is consulted and no policy version can produce it. A recorded reason
   outside the recipe's four is out of scope for this recipe and yields
   `unverifiable` with cause `reason_outside_recipe`. It is never `differs`:
   reporting a disagreement with a program that did not decide the entry would
   be a claim stronger than the evidence (article 2). Any later reason added to
   the published enumeration is likewise out of scope until a recipe that
   defines it is minted.
6. Otherwise compare the computed triple with the recorded triple. Equality is
   `confirmed`, inequality is `differs`, and a failure to check is
   `unverifiable` with its cause: `members_absent` when the record carries no
   `evaluation_recipe` or no `principal_references`,
   `evaluation_recipe_unsupported` when it names a recipe this text does not
   define, `policy_unparseable` when the bytes fail rule 1 or rule 2.

## What `confirmed` establishes

That the named record's triple is internally consistent with the archived
policy bytes under this recipe and the recorded inputs. It does not establish
historical group membership, that the actual arguments matched a
boundary-supplied digest, receipt of the answer, execution of the effect,
grant validity after a restart, or integrity against a writer able to replace
the store (article 7).
