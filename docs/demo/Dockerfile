# SPDX-License-Identifier: Apache-2.0
#
# The machine the recording is made on: the vhs renderer, uv, Python 3.12 as
# `python3`, and an ordinary account with an empty home directory. Nothing of
# sayfirst is in the image; the tape installs it from the index, as a reader
# would. Both base images are pinned by digest, so a render made later starts
# from the same bytes.
FROM ghcr.io/astral-sh/uv:0.12.5@sha256:e85be844203885286c60ffad8a858d48afb6c5a5c237ca0e67f12e74b8f174b1 AS uv

FROM ghcr.io/charmbracelet/vhs:v0.12.1@sha256:ea49a6a1c529be83153e88321892b5585964418f0b9055e8c1e0d732194234a3

COPY --from=uv /uv /uvx /usr/local/bin/

# Python 3.12, the oldest the project supports, installed where every account
# can read it and named `python3` ahead of the base image's own interpreter.
ENV UV_PYTHON_INSTALL_DIR=/opt/python
RUN uv python install 3.12 \
    && ln -s "$(uv python find 3.12)" /usr/local/bin/python3 \
    && useradd --create-home --uid 1000 --shell /bin/bash demo

USER demo
WORKDIR /home/demo
ENV HOME=/home/demo \
    PATH=/home/demo/.local/bin:/usr/local/bin:/usr/bin:/bin \
    UV_PYTHON_DOWNLOADS=never

ENTRYPOINT ["/usr/bin/vhs"]
