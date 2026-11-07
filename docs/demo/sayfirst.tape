# SPDX-License-Identifier: Apache-2.0
#
# A selection of the sayfirst 0.3.3 quickstart, recorded. Every command shown is
# typed into a real shell, and what follows it is what that command printed: the
# tape installs the published distributions, starts the daemon, and asks it. The
# hidden lines only create the program file and clear the screen between scenes.
# Rendered by render.sh, which checks the transcript before keeping anything.
#
# A refused call raises inside the governed program, and its traceback is long;
# the tape sends the program's error stream to err.txt and shows its last line,
# which is the outcome.

Output sayfirst.gif
Output sayfirst.webm
Output sayfirst.txt

Set Shell "bash"
Set FontSize 16
Set Width 1360
Set Height 600
Set Padding 24
Set TypingSpeed 18ms
Set WaitTimeout 180s
Set CursorBlink false

Hide
Type `mkdir ~/agent && cd ~/agent && printf 'import subprocess\n\nsubprocess.run(["echo", "hello"], check=True)\n' > my_agent.py && clear`
Enter
Wait
Show

Type "# install the client, the daemon and its operator surface: three commands, one environment"
Enter
Type "uv tool install sayfirst-cli==0.3.3 \"
Enter
Type "  --with-executables-from sayfirst-control-plane==0.3.3 --with-executables-from sayfirstd==0.3.3"
Enter
Wait
Sleep 2s

Hide
Type "clear"
Enter
Wait
Show

Type "# start a control plane: it writes a starter policy and answers on a local socket"
Enter
Type "sayfirst-daemon up --quickstart"
Enter
Wait
Sleep 3s

Hide
Type "clear"
Enter
Wait
Show

Type "# a program you already have"
Enter
Type "cat my_agent.py"
Enter
Wait
Sleep 1s
Type "# the starter policy allows starting a process: the program runs"
Enter
Type "sayfirst instrument run --pack subprocess --scope local -- python3 my_agent.py"
Enter
Wait
Sleep 2s

Type "# one word in the policy: allow becomes deny; nothing is restarted"
Enter
Type `sed -i 's/outcome = "allow"/outcome = "deny"/' ~/.sayfirst/quickstart/policy.toml`
Enter
Wait
Type `sayfirst instrument run --pack subprocess --scope local -- python3 my_agent.py 2> err.txt; echo "exit $?"`
Enter
Wait
Type "tail -n 1 err.txt"
Enter
Wait
Sleep 3s

Hide
Type "clear"
Enter
Wait
Show

Type "# deny becomes suspend: nothing runs until a person answers"
Enter
Type `sed -i 's/outcome = "deny"/outcome = "suspend"/' ~/.sayfirst/quickstart/policy.toml`
Enter
Wait
Type `sayfirst instrument run --pack subprocess --scope local -- python3 my_agent.py 2> err.txt; echo "exit $?"`
Enter
Wait
Type "tail -n 1 err.txt"
Enter
Wait
Sleep 2s
Type "approval=$(grep -oE '[0-9a-f-]{36}$' err.txt)"
Enter
Wait
Type `sayfirst approvals approve --approval "$approval" --scope local --reason "checked by hand"`
Enter
Wait
Sleep 2s
Type "# the one run that person authorised"
Enter
Type "sayfirst instrument run --pack subprocess --scope local -- python3 my_agent.py"
Enter
Wait
Sleep 3s

Hide
Type "clear"
Enter
Wait
Show

Type "# export the chain the daemon kept to a bundle that can be checked offline"
Enter
Type `sayfirst evidence export --scope local --from 1 --out bundle.json; echo "exit $?"`
Enter
Wait
Sleep 2s
Type "# the epoch is still open, so coverage is unknown and the check says so: exit 7, could not check, not broken"
Enter
Sleep 2s
Type "# with no control plane to ask, the effect does not happen: could not ask, never a denial"
Enter
Type "sayfirst-daemon down"
Enter
Wait
Type `sayfirst instrument run --pack subprocess --scope local -- python3 my_agent.py 2> err.txt; echo "exit $?"`
Enter
Wait
Type "tail -n 1 err.txt"
Enter
Wait
Sleep 4s
