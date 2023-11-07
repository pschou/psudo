# psudo - Parallel Remote SUDO

This is a single use program to run a shell script remotely using a parallel shell:

Usage:
```
$ ./psudo
Parallel Remote SUDO, Version (https://github.com/pschou/psudo)
Usage:
  psudo [flags] [args for script...]
Flags:
  -A    Disable SSH agent forwarding
  -H string
        List of hosts defined in a quoted string "host1, host2"
  -c string
        Command to execute remotely
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
        Script to execute remotely
  -u string
        Use this user rather than the current user
Examples:
  psudo -c "date"  # print the date (for checking that the clocks are matching)
  psudo -s "script.sh" -- file:out  # upload the file "out" and execute the script with this as an arg
  psudo -c tar -- -C /tmp -xvzf file:data.tgz  # extract the uploaded tar+gz file into /tmp
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
