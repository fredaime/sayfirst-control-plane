# SPDX-License-Identifier: Apache-2.0
"""Article 6 names documentation duties, so a guard reads the document."""

from __future__ import annotations

import re
from pathlib import Path

from sayfirst_control_plane.settings import DEFAULT_GROUP_LIFETIME_SECONDS, EVERYONE_GROUPS

REPOSITORY = Path(__file__).resolve().parents[4]
DEPLOYMENT = REPOSITORY / "docs" / "deployment.md"
SECURITY = REPOSITORY / "SECURITY.md"


def _flat(text: str) -> str:
    """One line, so a duty written as a sentence survives Markdown's wrapping."""
    return " ".join(text.replace("\n> ", " ").replace("> ", "").split())


def _sections(text: str) -> dict[str, str]:
    sections: dict[str, str] = {}
    heading = ""
    for line in text.splitlines():
        if line.startswith("#"):
            heading = line.lstrip("#").strip().lower()
            sections[heading] = ""
        elif heading:
            sections[heading] += line + "\n"
    return sections


def test_the_deployment_documentation_names_each_form_and_the_lifetime() -> None:
    """Article 6, rules Doc1 to Doc4: each duty is a heading a test can find."""
    text = DEPLOYMENT.read_text(encoding="utf-8")
    sections = _sections(text)
    for form in ("bare host", "sidecar", "node agent"):
        matching = [body for heading, body in sections.items() if form in heading]
        assert matching, form
        # The whole sentence Doc1 asks for, in each form's own section, not a
        # fragment of it in one of them.
        assert any(
            "imports the host's meaning of identity: the uids the daemon sees are the "
            "host kernel's, a container's uid that the host maps is admitted as that "
            "host uid, and one it does not map is refused as unmapped" in _flat(body)
            for body in matching
        ), form
    flat = _flat(text)
    assert "the socket file's permissions are the admission list" in flat.lower()
    assert "curl --unix-socket" in text
    assert (
        "a group membership revoked in the directory takes effect on a live connection "
        f"within `group_lifetime_seconds` (default {DEFAULT_GROUP_LIFETIME_SECONDS} seconds), "
        "plus the host's name-service cache, which this daemon neither controls nor observes"
    ) in flat
    assert "a grant already issued lasts its own lifetime (article 10)" in flat
    assert (
        "Policies bind group names; canonicalising them across directory services is the "
        "administrator's responsibility."
    ) in flat


def test_the_deployment_documentation_states_the_tooling_cost_as_accepted() -> None:
    """Article 6, rule Doc2: the cost is stated, not filed as a limitation to fix."""
    text = DEPLOYMENT.read_text(encoding="utf-8")
    assert "ssh -L" in text
    assert "no browser reaches" in _flat(text).lower()
    assert re.search(r"accepted cost|cost is accepted", text, re.IGNORECASE)


def test_the_deployment_documentation_states_what_a_credential_means() -> None:
    """Article 6, rule Doc5: the fd-passing caveat, the privilege tool, the pid."""
    text = DEPLOYMENT.read_text(encoding="utf-8")
    lowered = _flat(text).lower()
    assert "file descriptor" in lowered
    assert "declared delegation" in lowered
    assert "diagnosis" in lowered and "decides nothing" in lowered
    for name in EVERYONE_GROUPS:
        assert f"`{name}`" in text, name


def test_the_deployment_documentation_states_what_macos_does_not_check() -> None:
    """Article 6, rule Doc6: the one item the guard cannot hold there."""
    text = DEPLOYMENT.read_text(encoding="utf-8")
    assert "acl: not checked on this platform" in _flat(text)
    assert "vacuous" in text.lower()


def test_the_security_policy_points_at_the_deployment_document() -> None:
    """Article 6, rule Doc7: the admission model already stated, now with a pointer."""
    text = SECURITY.read_text(encoding="utf-8")
    assert "docs/deployment.md" in text
    assert "The socket file's permissions **are** the admission list" in _flat(text)


def test_the_deployment_documentation_says_what_the_daemon_creates_and_at_what_mode() -> None:
    """Article 6, rules L2 and S4: the table says of every level what it says of one."""
    flat = _flat(DEPLOYMENT.read_text(encoding="utf-8"))
    assert "the daemon, every level it creates at `0700`" in flat
    assert (
        "a per-user daemon creates every level of its parent directory at `0700`, "
        "whatever the umask it inherited"
    ) in flat


def test_the_deployment_documentation_states_ownership_after_the_drop_in_one_place() -> None:
    """Articles 2, 7 and 8, rule L2a: what the packager owes, and what the daemon checks as.

    The first root run of system mode found three things the document did not
    say, and an operator following it exactly got a daemon that started healthy
    and never served a decision. They are one rule with three faces — who owns
    the policy file, who creates the evidence root, and which group the daemon
    drops to — so the document states them under one heading a test can find,
    rather than in three places that would drift apart.
    """
    sections = _sections(DEPLOYMENT.read_text(encoding="utf-8"))
    body = _flat(sections["ownership after the drop"])
    # The policy file: root's, readable by `run_as` through a group of its own.
    assert "`[policy] path`" in body
    assert "readable by `run_as` through a group it is a member of" in body
    assert "`root:sayfirst 0640`" in body
    assert "never changes the owner or the mode of the policy file" in body
    # The evidence root: the packager's directory, the daemon's files.
    assert "`[evidence] path`" in body
    assert "the packager or the administrator creates it, owned by `run_as`" in body
    assert "never the daemon" in body
    assert "created after the drop as `run_as`" in body
    assert "`evidence_root_unusable`" in body
    # The group after the drop, and its consequence for the packager.
    assert "drops to `run_as`'s own group" in body
    assert "never takes `socket.group`" in body
    assert "is not a member of the admission group has no access through that group" in body
    # The store as a whole: the parents it could be replaced through, and the
    # chains — the ones present are proved, and a scope no rule names is served
    # and recorded on a chain created then. The claim is about what is there.
    assert "the same walk as the socket directory's" in body
    assert "scope of a decision is the caller's field, not the policy's" in body
    assert "no start check can enumerate the chains" in body
    assert "whatever scope it belongs to, named by a rule or not" in body
    assert "created on first use, as `run_as`, at `0600`" in body
    # The check is made by the account that will live with the answer.
    assert "after the drop and before the daemon listens" in body
    assert "`policy_unavailable_at_start`" in body
    assert "naming the path and the account that could not read it" in body
    # And the example configuration names both sections, so following the
    # document exactly is following this rule exactly.
    # (Read from the whole document: the example's SPDX comment line looks
    # like a heading to the section splitter above.)
    example = _flat(DEPLOYMENT.read_text(encoding="utf-8")).partition("## Starting the daemon")[2]
    assert '[policy] path = "/etc/sayfirst/policy.toml"' in example
    assert '[evidence] path = "/var/lib/sayfirst/evidence"' in example


def test_every_start_refusal_the_daemon_can_exit_with_is_published() -> None:
    """Article 2: a reason the operator reads in a document, not in a traceback.

    `docs/deployment.md` promises "one reason on standard error and exits 78"
    and then lists the reasons. A reason the daemon can exit with and the list
    does not carry is a promise the document does not keep, and a reason the
    list carries and the daemon cannot exit with is one the operator will wait
    for forever.
    """
    from sayfirst_control_plane.settings import START_REFUSALS

    flat = _flat(DEPLOYMENT.read_text(encoding="utf-8"))
    published = flat.partition("it writes one reason on standard error and exits 78.")[2]
    assert published, "the document does not say what a refused start writes"
    listed = set(re.findall(r"`([a-z_]+)`", published.partition(".")[0] + "."))
    assert listed == set(START_REFUSALS), {
        "published and unreachable": sorted(listed - set(START_REFUSALS)),
        "reachable and unpublished": sorted(set(START_REFUSALS) - listed),
    }
