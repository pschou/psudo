# psudo - Parallel Remote SUDO

This is a single use program to run a shell script remotely using a parallel shell:

Usage:
```
$ ./psudo
Missing host list
Parallel Remote SUDO, Version  (https://github.com/pschou/psudo)
Usage:
  psudo [opts] -s script.sh [args for script...]
  psudo [opts] -c "command string" [args...]
  psudo [opts] command [args...]
Flags:
  -A    Disable SSH agent forwarding
  -H string
        List of hosts defined in a quoted string "host1, host2"
  -c string
        If present, then commands are read from string.  Being that this is quoted, it allows globbing.
        If there are arguments after the string, they are assigned to the positional parameters,
        starting with $0.
  -d    Turn on script debugging
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
        Use this user rather than the current user
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

Example:
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
