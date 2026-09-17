# SPDX-License-Identifier: Apache-2.0
"""Make this directory an import root for the fixture modules its subdirectories share.

pytest puts a test file's own directory on the import path and nothing above
it, so a module beside this file — `foreign_doubles.py`, `digit_mask_redactor.py`
— is importable from a test in this directory and not from one under `unit/`
or `contract/`, unless a test from here happened to be collected first. Loading
this file puts this directory on the path for every test under it, in the
order the run is collected or one file at a time, which is what makes a
fixture shared by two subdirectories reachable from both. It declares no
fixture of its own.
"""
