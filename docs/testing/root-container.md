<!-- SPDX-License-Identifier: Apache-2.0 -->
# The root container the system-mode guards need

`assemble()` refuses system mode when `geteuid()` is not 0 (rule M3), so on an
ordinary runner every claim about what system mode *does* — the privilege drop
of article 7, the per-connection refusal of article 8, the evidence pipeline of
article 10 — is a claim about code that has never executed. This is the
throwaway container in which it does.

Nothing here is mounted from a home directory, and the repository goes in as a
copy rather than a bind mount, so a guard that writes cannot reach the tree it
was built from.

## The recipe

From a clean checkout, with `uv` on the path:

```sh
ctx=$(mktemp -d)
mkdir "$ctx/repo"
git archive --format=tar HEAD | tar -x -C "$ctx/repo"
cp "$(command -v uv)" "$ctx/uv"
cat > "$ctx/Dockerfile" <<'EOF'
# SPDX-License-Identifier: Apache-2.0
FROM python:3.12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends acl passwd \
 && rm -rf /var/lib/apt/lists/*
COPY uv /usr/local/bin/uv
WORKDIR /srv/lt
COPY repo/ /srv/lt/
RUN uv sync --frozen --all-packages --python /usr/local/bin/python3.12
EOF
docker build -t lt-rootmode:local "$ctx"
```

`acl` carries `setfacl`, which the ancestor guard of rule S4 asserts is present
rather than skipping without it. The interpreter is named outright so the image
is what runs the suite and nothing is fetched to replace it. `--all-packages` is
not a preference: the workspace root declares no member as a dependency, so a
plain `uv sync` installs none of them and the suite cannot collect at all.

## The accounts the guards name

The guards assert these exist and fail naming what is missing, because a
container that forgot them is a container that would otherwise report a run of
skips as a pass (article 2).

```sh
groupadd sayfirst-admitted
groupadd sayfirst-daemon
useradd -g sayfirst-daemon -G sayfirst-admitted -M -s /usr/sbin/nologin sayfirst-daemon
useradd -m -G sayfirst-admitted sayfirst-client
useradd -m sayfirst-outsider
```

`sayfirst-daemon` is the account the daemon drops to; its own group is
`sayfirst-daemon` and it is a member of the admission list, which is what makes
the drop of article 7 provable — the two groups differ, so a daemon that took
the admission list as its primary group is visible in `/proc/<pid>/status`.
`sayfirst-client` is a governed principal: in the admission group, and no writer
of the policy. `sayfirst-outsider` is outside the admission group and is refused
by the kernel at `connect()`.

Each name can be overridden — `SAYFIRST_ROOT_GUARD_RUN_AS`,
`SAYFIRST_ROOT_GUARD_GROUP`, `SAYFIRST_ROOT_GUARD_CLIENT`,
`SAYFIRST_ROOT_GUARD_OUTSIDER` — for a host whose account names are not free.

## Running the guards

```sh
docker run --rm lt-rootmode:local sh -c '
  groupadd sayfirst-admitted && groupadd sayfirst-daemon
  useradd -g sayfirst-daemon -G sayfirst-admitted -M -s /usr/sbin/nologin sayfirst-daemon
  useradd -m -G sayfirst-admitted sayfirst-client
  useradd -m sayfirst-outsider
  uv run --frozen --all-packages pytest -rs --junitxml=/tmp/report.xml \
    packages/contract/tests/identity packages/control-plane/tests/identity
  uv run --frozen --all-packages python scripts/require_platform_guards.py \
    --junit=/tmp/report.xml --privilege=root \
    --tree=packages/contract/tests/identity \
    --tree=packages/control-plane/tests/identity
'
```

The second command is what makes the first one's skips mean something: `-rs`
reports a skip and does not fail on one, so a run in which every root-gated
guard skipped exits 0. `--privilege=root` says this runner is the one that owes
them, and a guard it did not hold fails the step by name.

## Cleaning up

```sh
docker image rm lt-rootmode:local
rm -rf "$ctx"
```

The container is `--rm`, so nothing of it survives the run.
