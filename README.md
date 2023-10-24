# psudo - Parallel Remote SUDO

This is a single use program to run a shell script remotely using a parallel shell:

Usage:
```
$ ./psudo --help
Usage of ./sudo-ssh:
  -d    Turn on script debugging
  -h string
        Read hosts from given host file
  -i string
        SSH identity file for login
  -p int
        Maximum concurrent connections allowed (default 4)
  -pw string
        Send password for line matching (default "^\\[sudo\\] password for ")
  -s string
        Script to execute remotely
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
