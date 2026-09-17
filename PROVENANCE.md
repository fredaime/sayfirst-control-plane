<!-- SPDX-License-Identifier: Apache-2.0 -->
# Provenance

Article 14 of [`CONSTITUTION.md`](CONSTITUTION.md): files that enter an open
repository of this project from a repository it does not hold enter by copy,
never by history rewriting, and every copy has a provenance review. That
review's record is private. What is public is the copyright holder and the
licence, and nothing more; `NOTICE` names every holder.

## The record

Material in this tree entered it that way. The note it carries, in the wording
article 14 requires and with nothing added to it, is:

copied from a private repository of the project; copyright holder: Frédéric Aime; licence: Apache-2.0

## Why the record is a file and not a commit message

[`SECURITY.md`](SECURITY.md) publishes this project by creating a repository
fresh from the reviewed tree, with no history behind it. A record kept only in
commit messages would not survive that act: the public repository would hold
material that arrived by copy and no account of how it arrived, or whoever
publishes would be pushed to carry a history across to supply one — which is
the leak article 0's fresh path exists to prevent. So the record is a tracked
file and it travels with the tree.

The guard that holds this rule reads the file, and holds any history the tree
sits on to the same note. A repository whose history records nothing of the
kind — the fresh one — is green on it without carrying anything across.
