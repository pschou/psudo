# psudo - Parallel Remote SUDO

Sometimes one needs to run a sudo command on multiple boxes, all of which may
or may not require a password entry.  The options such as pssh will not handle
the additional sudo password prompt.  Other tools such as Ansible may attempt
to login to all the boxes with a given password-- if your domain has lockout
limits in place, one risks getting their account locked for one mistyped
password.  So this tool was built to handle such a case in which both login and
sudo password prompts are handled, and if a password is mistyped that only one
password-attempt is made before cutting connections.


## Features

- Avoid password lockouts by test each host and failing fast after the first password failure

- Handle parallel commands sent at once, to speed up operations on multiple systems

- Ansi colors are preserved, when colors are sent, they are preserved and prefixed with the host

- Optional ability to uploads multiple files for use as arguments (deleted upon finish)

- Can run a `-c "command"` option (this translates to a `bash -c "command"` on
  the target).  Note, with this option the entire command string must be wrapped
in quotes and special characters escaped before the shell passes these
arguments to the executable.

- With the `-s script.sh` flag, a script is uploaded and then executed (translates to `bash script.sh`)

- Run a generic command using the shell given upon creating an ssh session.  By not requiring wrapping quotes, one can work directly from the control system leveraging the local shell parsing of args to capture the args to be sent to each box.

## Functioning

Parallel SUDO will login to a list of boxes, test to verify that sudo is indeed
working and that a password is accepted.  Once this is verified, the commands
can then be ran in parallel on the hosts.

For convenience of deploying of software packages, the PSUDO gives the ability
to both send files and commands in the same session.  This way one does not
have to connect once to first upload a file and then connect again to install
or operate on the uploaded file.  A good example of such a use case may be a
yum install of an rpm which is on the master node with a shared file space.
The command to install this can be simplified down to something as short as:
`psudo -h hostfile sudo yum install file:program.rpm -y`


## Usage
```
$ ./psudo -help
Parallel Remote SUDO, Version 0.1.20231108.2120 (https://github.com/pschou/psudo)
Usage:
  psudo [opts] -s script.sh [args for script...]
  psudo [opts] -c "command string" [args...]
  psudo [opts] command [args...]
Flags:
  -A    Disable SSH agent forwarding
  -H string
        List of hosts defined in a quoted string "host1, host2"
  -b    Batch mode, disable prompt after prechecks are done if everything passes
  -c string
        If present, then commands are read from string.  Being that this is quoted, it allows globbing.
        If there are arguments after the string, they are assigned to the positional parameters,
        starting with $0.
  -d    Turn on script debugging
  -f    Force mode, disable prechecks and if login attempts are limited this may lock you out.
  -h string
        Read hosts from given host file
  -i string
        SSH identity file for login, the private key for single use
  -p int
        Maximum concurrent connections allowed (default 4)
  -pw string
        Send password for line matching (default "^\\[sudo\\] password for ")
  -s string
        If present, the script is uploaded and then executed remotely. If there are arguments after the
        string, they are assigned to the positional parameters, starting with $1.
  -sh string
        BaSH path to use for executing the script (-s) or command (-c) flags (default "/bin/bash")
  -u string
        Use this user rather than the current user for ssh connect
  -w duration
        Timeout when probing for TCP listening port (default 5s)
Arg Options:
  file:f.tgz - Upload a file into a temporary file and pass as an arg.
  arg:-c     - Specify an argument to feed into the script (default if not specified)
  arg:file:t - Stacking is necessary if an arg must have the prefix "file:"
Examples:
  psudo -H host1,host2 date  # Print the date, ie: checking that the clocks are matching.
  psudo -h hf -s script.sh -- -c              # Upload and run script.sh and pass a '-c' arg as $1.
  psudo -h hf -s script.sh arg:-c file:out    # " and pass in an uploaded file path as second arg.
  psudo -h hf tar -C /tmp -zvxf file:f.tgz    # Call a command with args.
  psudo -h hf -c "echo hello; echo world"     # A string of commands.
  psudo -h hf -c 'mv $0 /tmp/a && mv $1 /dev/shm/b && chmod 755 /dev/shm/b' file:aFile file:bFile
    # Complex example sending two files into different locations and changing mode
```

## Example

```
$ ./psudo -h hosts -s script.sh
1 hosts loaded
Enter Username [default: schou]:
Enter Password:
10.12.128.249:22 -- Connecting
10.12.128.249 hello world Mon Oct 23 22:23:46 EDT 2023
10.12.128.249 Light red color
10.12.128.249            _..._
10.12.128.249          .'     '.
10.12.128.249         /  _   _  \
10.12.128.249         | (o)_(o) |
10.12.128.249          \(     ) /
10.12.128.249          //'._.'\ \
10.12.128.249         //   .   \ \
10.12.128.249        ||   .     \ \
10.12.128.249        |\   :     / |
10.12.128.249        \ `) '   (`  /_
10.12.128.249      _)``".____,.'"` (_
10.12.128.249      )     )'--'(     (
10.12.128.249       '---`      `---`
10.12.128.249 Reset Colors
10.12.128.249 total 20
...
```

## Special command considerations

This cases where commands are sent on the command line, one should expect the
value to be parsed and sent either as a fully escaped set of args and, or as a
parsed string remotely.  To demonstrate this point, see the examples below:

### Sends everything escaped
```
$ psudo -H localhost echo hi \; echo there
```

Output:
```
hi \; echo there
```

Use cases for this is when a single binary, such as `tar`, is invoked remotely
with arguments passed in on the command line.

### The quoted section get parsed
```
$ psudo -H localhost -c "echo hi ; echo there"
```

Output:
```
hi
there
```

Use cases for this is when one or more commands are all being sent as a string,
the full string gets broken down remotely instead of locally.
