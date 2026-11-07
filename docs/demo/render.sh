#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Render the quickstart recording: docs/demo/sayfirst.gif and sayfirst.webm.
#
#   docs/demo/render.sh
#
# The tape runs in the image docs/demo/Dockerfile describes, as an ordinary
# account with an empty home directory, so nothing installed on this machine
# reaches it: it installs sayfirst 0.3.3 from the index as a reader would. The
# recording is kept only when its transcript shows each outcome the tape asks
# for, in order, and the GIF is under 2 MB; otherwise nothing here is written.
# Needs Docker, Python 3, GNU tar and stat, and network access to the
# container registries, the Python downloads uv uses, and the package index.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly image="sayfirst-demo-render"
readonly container="sayfirst-demo-render-$$"
readonly gif_limit=2000000
readonly spdx="SPDX-License-Identifier: Apache-2.0"
work="$(mktemp -d)"

cleanup() {
  docker rm --force "${container}" >/dev/null 2>&1 || true
  rm -rf "${work}"
  rm -f "${here}/.sayfirst.gif.new" "${here}/.sayfirst.webm.new"
}
trap cleanup EXIT

# Files cross as tar streams on standard input and output, so the shell reads
# and writes them: a confined Docker client (the snap package, for one) cannot
# reach every path on this machine. The build context is the Dockerfile alone.
tar --create --file=- --directory="${here}" Dockerfile |
  docker build --quiet --tag "${image}" - >/dev/null

# The recordings carry the licence identifier in the form each format allows:
# the WebM as a metadata tag, written here by the image's own ffmpeg, and the
# GIF as a comment extension, written below.
docker create --name "${container}" --entrypoint sh "${image}" -c \
  "vhs sayfirst.tape && ffmpeg -v error -i sayfirst.webm -c copy -metadata comment='${spdx}' tagged.webm && mv tagged.webm sayfirst.webm" \
  >/dev/null
tar --create --file=- --mode=a+r --directory="${here}" sayfirst.tape |
  docker cp - "${container}:/home/demo"
docker start --attach "${container}"
for output in sayfirst.gif sayfirst.webm sayfirst.txt; do
  docker cp "${container}:/home/demo/${output}" - | tar --extract --file=- --directory="${work}"
done

# The transcript, in the order the tape asks for each outcome. A line missing,
# or out of order, means the run was not the one the tape types, and nothing
# is kept. An entry starting with "=" is a whole line; any other is part of one.
expected=(
  "+ sayfirst-cli==0.3.3"
  "+ sayfirst-control-plane==0.3.3"
  "+ sayfirstd==0.3.3"
  "SayFirst Control Plane ready"
  "integrity grade: observability"
  "=hello"
  "=exit 1"
  "sayfirst_boundary.errors.Denied: denied: process.spawn (policy_denies"
  "=exit 5"
  "sayfirst_boundary.errors.Suspended: suspended: process.spawn awaits approval"
  "state: approved"
  "=hello"
  "chain: intact"
  "coverage: unknown"
  "saved: bundle.json"
  "=exit 7"
  "SayFirst Control Plane stopped"
  "=exit 4"
  "sayfirst_boundary.errors.CouldNotAsk: could not ask"
)
python3 - "${work}/sayfirst.txt" "${expected[@]}" <<'PYTHON'
import sys

transcript_path, *expected = sys.argv[1:]
# The text output repeats the screen once per frame it keeps, so a line is
# found many times; what is checked is that each expected line appears after
# the one found before it, in the order the frames were written.
lines = [line.strip() for line in open(transcript_path, encoding="utf-8").read().splitlines()]


def matches(wanted: str, line: str) -> bool:
    return line == wanted[1:] if wanted.startswith("=") else wanted in line


position = 0
for wanted in expected:
    for index in range(position, len(lines)):
        if matches(wanted, lines[index]):
            position = index + 1
            break
    else:
        sys.exit(f"render: the transcript never shows {wanted!r} after line {position}")
if any("command not found" in line for line in lines):
    sys.exit("render: the transcript shows a command the shell could not find")
PYTHON

# The GIF's comment extension goes right after the header, the logical screen
# descriptor and the global colour table, where the format allows one.
python3 - "${work}/sayfirst.gif" "${spdx}" <<'PYTHON'
import sys

path, text = sys.argv[1], sys.argv[2].encode("ascii")
data = open(path, "rb").read()
if data[:6] not in (b"GIF87a", b"GIF89a"):
    sys.exit("render: sayfirst.gif is not a GIF")
flags = data[10]
end = 13 + (3 * 2 ** ((flags & 7) + 1) if flags & 0x80 else 0)
comment = b"\x21\xfe" + bytes([len(text)]) + text + b"\x00"
open(path, "wb").write(b"GIF89a" + data[6:end] + comment + data[end:])
PYTHON

size="$(stat --format=%s "${work}/sayfirst.gif")"
if (( size >= gif_limit )); then
  echo "render: sayfirst.gif is ${size} bytes, over the ${gif_limit}-byte limit" >&2
  exit 1
fi

# Each file is written beside its final name and then renamed over it, so an
# interruption leaves the earlier recording whole rather than half replaced.
cp "${work}/sayfirst.gif" "${here}/.sayfirst.gif.new"
cp "${work}/sayfirst.webm" "${here}/.sayfirst.webm.new"
mv -f "${here}/.sayfirst.gif.new" "${here}/sayfirst.gif"
mv -f "${here}/.sayfirst.webm.new" "${here}/sayfirst.webm"
echo "render: wrote ${here}/sayfirst.gif (${size} bytes) and ${here}/sayfirst.webm ($(stat --format=%s "${here}/sayfirst.webm") bytes)"
