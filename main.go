package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/alessio/shellescape"
	"github.com/bramvdbogaerde/go-scp"
	ansi "github.com/leaanthony/go-ansi-parser"
	"github.com/remeh/sizedwaitgroup"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var (
	disableColors  = flag.Bool("nc", false, "Turn off colors on the reply lines")
	userSetting    = flag.String("u", "", "Use this user rather than the current user for ssh connect")
	hostListFile   = flag.String("h", "", "Read hosts from given host file")
	hostListString = flag.String("H", "", "List of hosts defined in a quoted string \"host1, host2\"")
	script         = flag.String("s", "",
		"If present, the script is uploaded and then executed remotely. If there are arguments after\n"+
			"the string, they are assigned to the positional parameters, starting with $1.")
	command = flag.String("c", "",
		"If present, then commands are read from string like an inline script.  Because the string\n"+
			"is quoted, it allows for globbing (ie: *.log).  If there are arguments after the string,\n"+
			"they are assigned to the positional parameters, starting with $0.")
	parallel      = flag.Int("p", 4, "Maximum concurrent connections allowed")
	parallelCache = flag.Int("pc", 40, "Max cached concurrent connections allowed")
	shell         = flag.String("sh", "/bin/bash", "BASH path to use for executing the script (-s) or command (-c) flags")
	sudo          = flag.String("sudo", "/usr/bin/sudo /usr/bin/true",
		"Command to use for privilage escilation precheck.  This command must return a 0 exit code.\n"+
			"Disable the sudo precheck by setting to \"\".")
	identity        = flag.String("i", "", "SSH identity file for login, the private key for single use")
	disableAgent    = flag.Bool("a", false, "Disable SSH agent forwarding")
	disablePrecheck = flag.Bool("f", false, "Force mode, disable prechecks-- if login attempts are limited this may lock you out.")
	batchMode       = flag.Bool("b", false, "Batch mode, disable prompt after prechecks are done if everything passes")
	debug           = flag.Bool("d", false, "Turn on script debugging")
	passwordMatch   = flag.String("match_pw", `^\[sudo\] password for `, "Send password for line matching")
	passcodeMatch   = flag.String("match_code", `^Passcode( or option|):`, "Send a passcode for line matching")
	timeout         = flag.Duration("w", 5*time.Second, "Timeout when probing for TCP listening port")

	// username for login
	username string

	// precompiled regexp for matching
	passwordRegex, passcodeRegex *regexp.Regexp

	// version set at compile time
	version string

	// output report metrics
	durations  []time.Duration
	exitCodes  []int
	lineCounts []int
	hostErrors []string

	clientCache []*ssh.Client
	clientOnce  []sync.Mutex
)

func main() {
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "Parallel Remote SUDO, Version", version, "(https://github.com/pschou/psudo)")
		_, exec := path.Split(os.Args[0])
		fmt.Fprintln(os.Stderr, "Usage:\n  "+exec+" [opts] -s script.sh [args for script...]\n  "+
			exec+" [opts] -c \"command string\" [args...]\n  "+
			exec+" [opts] command [args...]\nFlags:")
		flag.PrintDefaults()

		fmt.Fprintln(os.Stderr, `Arg Options:
  file:f.tgz - Upload a file into a temporary file and pass as an arg.
  arg:-c     - Specify an argument to feed into the script (default if not specified)
  arg:file:t - Stacking is necessary if an arg must have the prefix "file:"
Examples:`+"\n  "+
			exec+" -H host1,host2 date  # Print the date, ie: checking that the clocks are matching.\n  "+
			exec+" -h hf -s script.sh -- -c              # Upload and run script.sh and pass a '-c' arg as $1.\n  "+
			exec+" -h hf -s script.sh arg:-c file:out    # \" and pass in an uploaded file path as second arg.\n  "+
			exec+" -h hf tar -C /tmp -zvxf file:f.tgz    # Call a command with args.\n  "+
			exec+" -h hf -c \"echo hello; echo world\"     # A string of commands.\n  "+
			exec+" -h hf -c 'mv $0 /tmp/a && mv $1 /dev/shm/b && chmod 755 /dev/shm/b' file:aFile file:bFile\n    "+
			"# Complex example sending two files into different locations and changing mode")
	}
	flag.Parse()

	if *parallelCache < *parallel {
		*parallelCache = *parallel
	}
	if strings.ToLower(strings.Join(flag.Args(), " ")) == "make me a sandwich" {
		egg()
	}
	if *hostListFile == "" && *hostListString == "" {
		failUsage("Missing host list")
	}
	if *script == "" && *command == "" && len(flag.Args()) == 0 {
		failUsage("Missing command to execute")
	}
	if *script != "" && *command != "" {
		failUsage("Must have specify a script or command, not both.")
	}
	if *script != "" {
		fh, err := os.Open(*script)
		if err != nil {
			log.Fatal("Unable to open script file", *script, "--", err)
		}
		fh.Close()
	}
	passwordRegex = regexp.MustCompile(*passwordMatch)
	passcodeRegex = regexp.MustCompile(*passcodeMatch)

	// Determine username to use
	if strings.TrimSpace(*userSetting) == "" {
		currentUser, err := user.Current()
		if err != nil {
			log.Fatalf(err.Error())
		}
		username = currentUser.Username
	} else {
		username = *userSetting
	}
	username = strings.TrimSpace(username)

	// Parse out the script args and make sure all the files are readable
	{
		for _, s := range flag.Args() {
			lower := strings.ToLower(s)
			switch {
			case strings.HasPrefix(lower, "file:"):
				fh, err := os.Open(s[5:])
				if err != nil {
					log.Fatal(err)
				}
				fh.Close()
			}
		}
	}

	// Host list from command line
	hostList := strings.FieldsFunc(*hostListString, func(c rune) bool {
		return c == ',' || c == ' ' || c == '\n' || c == '\r' || c == '\t'
	})

	if *hostListFile != "" {
		// Read host list from file
		fileHostList, err := readLines(*hostListFile)
		if err != nil {
			log.Fatal(err)
		}
		hostList = append(hostList, fileHostList...)
	}

	hostList = dedup(hostList)
	originalHostCount := len(hostList)
	{ // Loop over hosts to verify that the TCP port is connectable
		var newHostList []string
		d := net.Dialer{Timeout: *timeout}
		for i, host := range hostList {
			if _, _, err := net.SplitHostPort(host); err != nil {
				host = net.JoinHostPort(host, "22")
				hostList[i] = host
			}
			conn, err := d.Dial("tcp", host)
			if err == nil {
				newHostList = append(newHostList, host)
				conn.Close()
				if *debug {
					fmt.Fprintln(os.Stderr, " ", host, " port open")
				}
			} else {
				fmt.Fprintln(os.Stderr, " ", host, " no reply")
			}
		}
		fmt.Fprintln(os.Stderr, len(newHostList), "hosts available out of", len(hostList), "loaded")
		hostList = newHostList
	}

	//fmt.Printf("%#v\n", hostList)
	if len(hostList) == 0 {
		return
	}

	// Build configuration for ssh
	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			//ssh.Password(pass),
			//ssh.KeyboardInteractive(SshInteractive),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	//fmt.Printf("config %#v\n", config)

	// Enable the use of an SSH agent
	var sshAgent *agent.ExtendedAgent
	if socket := os.Getenv("SSH_AUTH_SOCK"); socket != "" && !*disableAgent {
		conn, err := net.Dial("unix", socket)
		if err != nil {
			log.Fatalf("Failed to open SSH_AUTH_SOCK: %v", err)
		}
		agentClient := agent.NewClient(conn)
		sshAgent = &agentClient
		config.Auth = append([]ssh.AuthMethod{ssh.PublicKeysCallback(agentClient.Signers)}, config.Auth...)
	}

	// Parse the identity from the private key for SSH login
	if *identity != "" {
		privateKey, err := os.ReadFile(*identity)
		if err != nil {
			log.Fatal(err)
		}
		key, err := ssh.ParsePrivateKey([]byte(privateKey))
		if err != nil {
			log.Fatal(err)
		}
		config.Auth = append([]ssh.AuthMethod{ssh.PublicKeys(key)}, config.Auth...)
	}

	AuthMethods := append(config.Auth, ssh.PasswordCallback(func() (secret string, err error) {
		return pass(), nil
	}))

	clientCache = make([]*ssh.Client, len(hostList))
	clientOnce = make([]sync.Mutex, len(hostList))

	/*
	 * Precheck: Do a log in and test the SUDO command on each host
	 */
	if !*disablePrecheck {
		fmt.Fprintln(os.Stderr, "Verifying sudo access on hosts...")
		var (
			passwordLock   sync.Mutex
			passwordLocked bool
			passcodeLock   sync.Mutex
			passcodeLocked bool
			precheckFail   bool

			connectCount, sudoCount int
			swg                     = sizedwaitgroup.New(*parallel * 2)
		)
		hostErrors = make([]string, len(hostList))
		for iHost, host := range hostList {
			swg.Add()
			go func(iHost int, host string) error {
				defer swg.Done()
				if precheckFail {
					return errors.New("skipped checks") // Shouldn't get here, but to be sure.
				}

				var (
					passwordTries int
					passcodeTries int
				)

				// Call back so we can get a count of the number of password tries
				passwordCallBack := func() (secret string, err error) {
					passwordLock.Lock()
					if precheckFail {
						os.Exit(1)
					}
					passwordLocked = true
					passwordTries++
					if passwordTries > 1 {
						precheckFail = true
						log.Fatal("SSH Login incorrect password")
					}
					return pass(), nil
				}

				// Setup the test config to send with the connection
				testConfig := &ssh.ClientConfig{
					User:            username,
					Auth:            append(config.Auth, ssh.PasswordCallback(passwordCallBack)),
					HostKeyCallback: ssh.InsecureIgnoreHostKey(),
				}
				client, err := ssh.Dial("tcp", host, testConfig)
				if precheckFail {
					return err
				}
				if err != nil {
					precheckFail = true
					fmt.Fprintln(os.Stderr, " ", host, " connect failed--", err)
					os.Exit(1)
					return err
				}
				if passwordLocked {
					passwordLocked = false
					passwordLock.Unlock()
				}
				if passcodeLocked {
					passcodeLocked = false
					passcodeLock.Unlock()
				}

				// Keep the first few sessions open in a cache to improve performance
				if iHost < *parallelCache {
					clientCache[iHost] = client
				} else {
					defer client.Close()
				}
				if *debug {
					fmt.Fprintln(os.Stderr, " ", host, " connected")
				}

				session, err := client.NewSession()
				if err != nil {
					fmt.Fprintln(os.Stderr, " ", host, " session failed--", err)
					return err
				}
				connectCount++
				if *debug {
					fmt.Fprintln(os.Stderr, " ", host, " session created")
				}
				defer session.Close()
				if sshAgent != nil {
					agent.ForwardToAgent(client, *sshAgent)
					agent.RequestAgentForwarding(session)
				}

				modes := ssh.TerminalModes{
					ssh.ECHO:          0,     // Disable echoing
					ssh.IGNCR:         1,     // Ignore CR on input.
					ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
					ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
				}
				if err := session.RequestPty("xterm", 1, term_width-len(host)-2, modes); err != nil {
					return err
				}

				var (
					stdin, _  = session.StdinPipe()
					stdout, _ = session.StdoutPipe()

					channelOpen = true
					closed      = make(chan bool)
				)
				passwordTries = 0
				passcodeTries = 0

				// Read the input from the reader and print it to the screen
				go func() {
					buff := new(bytes.Buffer)
					rdr := make([]byte, 32<<10)
					var doChomp bool
					for n, err := stdout.Read(rdr); channelOpen && (n > 0 || err == nil); n, err = stdout.Read(rdr) {
						//fmt.Printf("read"+num+" %s\n", string(rdr[:n]))
						buff.Write(rdr[:n])
						for {
							str, err := buff.ReadString('\n')
							if doChomp && strings.TrimSpace(str) == "" {
								doChomp = false
								continue
							}
							// Match for the sudo prompt
							if passwordRegex.Match([]byte(str)) {
								passwordTries++
								if passwordTries > 1 {
									hostErrors[iHost] = "SUDO incorrect password"
									fmt.Fprintln(os.Stderr, " ", host, " SUDO incorrect password")
									return
								}
								passwordLock.Lock()
								passwordLocked = true
								fmt.Fprintf(stdin, "%s\n", pass())
								if *debug {
									fmt.Fprintln(os.Stderr, " ", host, " sent password to sudo prompt")
								}
								doChomp = true
								continue
							}
							// Match for the passcode prompt
							if passcodeRegex.Match([]byte(str)) {
								passcodeTries++
								if passcodeTries > 1 {
									hostErrors[iHost] = "Incorrect pass CODE"
									fmt.Fprintln(os.Stderr, " ", host, " Incorrect pass CODE")
									return
								}
								passcodeLock.Lock()
								passcodeLocked = true
								fmt.Fprintf(stdin, "%s\n", code())
								if *debug {
									fmt.Fprintln(os.Stderr, " ", host, " sent password to sudo prompt")
								}
								doChomp = true
								continue
							}

							if err != nil {
								// This may be a partial line, put it back in the buffer and break the loop
								buff.Write([]byte(str))
								break
							}
						}
					}
					closed <- true
				}()

				if *sudo != "" {
					// Do sudo precheck if a command is specified
					session.Start(*sudo)
					err = session.Wait()
					<-closed
					if err != nil {
						if passwordLocked {
							precheckFail = true
							os.Exit(1)
						}
						fmt.Fprintln(os.Stderr, " ", host, " sudo failed--", err)
					} else if passwordTries < 2 {
						sudoCount++
						//newHostList = append(newHostList, host)
						if *debug {
							fmt.Fprintln(os.Stderr, " ", host, " sudo succeeded")
						}
					}
				}
				if passwordLocked {
					passwordLocked = false
					passwordLock.Unlock()
				}
				if passcodeLocked {
					passcodeLocked = false
					passcodeLock.Unlock()
				}
				return nil
			}(iHost, host)
			/*if err != nil {
				fmt.Fprintln(os.Stderr, " ", host, " err:", err)
				os.Exit(1)
			}*/
		}
		swg.Wait()
		// TODO: Add list by host on what failures were seen using hostErrors array

		if *sudo != "" {
			fmt.Fprintln(os.Stderr, "Login was successful on", connectCount, "hosts and sudo on", sudoCount, "hosts")
		} else {
			fmt.Fprintln(os.Stderr, "Login was successful on", connectCount, "hosts and no sudo check was done")
			sudoCount = connectCount
		}
		//	if !*batchBatchMode {
		if !*batchMode || originalHostCount > sudoCount {
			if !confirm("Continue? ") {
				os.Exit(1)
			}
		}
		//}
		//hostList = newHostList
	}

	shortList := shorten(hostList)
	durations = make([]time.Duration, len(shortList))
	exitCodes = make([]int, len(shortList))
	lineCounts = make([]int, len(shortList))
	hostErrors = make([]string, len(shortList))
	config.Auth = AuthMethods

	/*
	 *  Main worker loop- loop over each host and sends out commands in parallel
	 */
	var (
		swg      = sizedwaitgroup.New(*parallel)
		swgCache = sizedwaitgroup.New(*parallelCache)
	)
	for i := 0; i < *parallelCache && i < len(hostList); i++ {
		swgCache.Add() // fill up the waitgroup
	}
	for i := *parallelCache; i < len(hostList); i++ {
		clientOnce[i].Lock() // lock the rest to avoid double connecting
	}
	// Pre login to hosts
	go func() {
		for i := *parallelCache; i < len(hostList); i++ {
			swgCache.Add()
			go func(i int) {
				defer clientOnce[i].Unlock()
				host := hostList[i]
				client, err := ssh.Dial("tcp", host, config)
				if err != nil {
					hostErrors[i] = fmt.Sprintf("%v", err)
				}
				clientCache[i] = client
			}(i)
		}
	}()

	for iHost, host := range hostList {
		hostColor, hostBgColor, hostStyle := getColour(iHost)
		swgCache.Done()
		swg.Add()
		go func(host string, iHost int) {
			defer swg.Done()

			clientOnce[iHost].Lock()
			client := clientCache[iHost]
			if client == nil {
				fmt.Fprintln(os.Stderr, s(ansi.String([]*ansi.StyledText{&ansi.StyledText{
					Label: host + " -- Failed", Style: ansi.Underlined | hostStyle,
					FgCol: hostColor, BgCol: hostBgColor,
				}})))
				return
			}
			defer client.Close()

			fmt.Fprintln(os.Stderr, s(ansi.String([]*ansi.StyledText{&ansi.StyledText{
				Label: host + " -- Connected", Style: ansi.Underlined | hostStyle,
				FgCol: hostColor, BgCol: hostBgColor,
			}})))

			// Attempt initial send to one client
			err := execute(strings.TrimSuffix(shortList[iHost], ":22"), client, sshAgent, iHost)
			if err != nil {
				hostErrors[iHost] = fmt.Sprintf("%v", err)
				//log.Println(host, err)
				return
			}
		}(host, iHost)
	}
	swg.Wait()
	fmt.Fprintln(os.Stderr, "--- Results ---")
	maxLen := 0
	for _, host := range shortList {
		if len(host) > maxLen {
			maxLen = len(host)
		}
	}
	maxLenStr := fmt.Sprintf("%d", maxLen)
	fmt.Fprintf(os.Stderr, "% -"+maxLenStr+"s  %s\n", "host", "ret  lines  duration")

	for i, host := range shortList {
		hostColor, hostBgColor, hostStyle := getColour(i)
		fmt.Fprintf(os.Stderr, "%s  %-4d %-6d %v %s\n",
			s(ansi.String([]*ansi.StyledText{&ansi.StyledText{
				Label: fmt.Sprintf("%-"+maxLenStr+"s", host), Style: hostStyle,
				FgCol: hostColor, BgCol: hostBgColor,
			}})),
			exitCodes[i], lineCounts[i], durations[i], hostErrors[i])
	}
}

func failUsage(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	flag.Usage()
	os.Exit(1)
}

// Send the script over the ssh connection
func execute(host string, client *ssh.Client, sshAgent *agent.ExtendedAgent, iHost int) error {
	hostColor, hostBgColor, hostStyle := getColour(iHost)

	// timer function
	start := time.Now()
	defer func() {
		durations[iHost] = time.Now().Sub(start)
	}()

	var srcName, dstFullName, dstShortName []string
	var tempFull, tempShort string
	if *script != "" {
		tempFull, tempShort = TempFileName("psudo-", ".sh")
		srcName = []string{*script}
		dstFullName = []string{tempFull}
		dstShortName = []string{tempShort}
	}

	var scriptArgs string
	{
		var args []string
		args = append(args, flag.Args()...)
		for i, s := range args {
			lower := strings.ToLower(s)
			switch {
			case strings.HasPrefix(lower, "arg:"):
				s = s[4:]
			case strings.HasPrefix(lower, "file:"):
				s = s[5:]
				ext := filepath.Ext(s)
				if len(ext) == 0 {
					ext = ".tmp"
				}
				srcName = append(srcName, s)
				dstFull, dstShort := TempFileName("psudo-file-", ext)
				dstFullName = append(dstFullName, dstFull)
				dstShortName = append(dstShortName, dstShort)
				s = dstFull
			}
			args[i] = shellescape.Quote(s)
		}
		scriptArgs = strings.Join(args, " ")
	}

	/*
	 * SSH session for transferring the files
	 */
	if len(srcName) > 0 {
		for iFile, Src := range srcName {
			cli, err := scp.NewClientBySSH(client)
			if err != nil {
				return err
			}

			if *debug {
				fmt.Println(s(ansi.String([]*ansi.StyledText{
					&ansi.StyledText{Label: host + " <", FgCol: hostColor, BgCol: hostBgColor, Style: hostStyle},
					&ansi.StyledText{Label: " Uploading file " + Src + " to " + dstFullName[iFile]},
				})))
			}
			fh, err := os.Open(Src)
			if err != nil {
				log.Println(host, "Error reading file locally:", err)
				return err
			}
			stat, err := fh.Stat()
			var fileMode string
			if stat.Mode()&0100 != 0 {
				fileMode = "0700"
			} else {
				fileMode = "0600"
			}
			err = cli.Copy(context.Background(), fh, dstFullName[iFile], fileMode, stat.Size())
			fh.Close()
			if err != nil {
				log.Println(host, "Error writing file remotely:", err)
				return err
			}

			if *debug {
				fmt.Println(s(ansi.String([]*ansi.StyledText{
					&ansi.StyledText{Label: host + " <", FgCol: hostColor, BgCol: hostBgColor, Style: hostStyle},
					&ansi.StyledText{Label: " Uploaded file " + Src + " to " + dstFullName[iFile]},
				})))
			}

			cli.Close()
		}
	}

	/*
	 * SSH session for running the script with password handling
	 */
	{
		session, err := client.NewSession()
		if err != nil {
			return err
		}
		defer session.Close()
		if sshAgent != nil {
			agent.ForwardToAgent(client, *sshAgent)
			agent.RequestAgentForwarding(session)
		}

		modes := ssh.TerminalModes{
			ssh.ECHO:          0,     // Disable echoing
			ssh.IGNCR:         1,     // Ignore CR on input.
			ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
			ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
		}
		if err := session.RequestPty("xterm", 1, term_width-len(host)-2, modes); err != nil {
			log.Println(host, "Request for pseudo terminal failed: %s", err)
			return err
		}
		//session.Setenv("SUDO_PROMPT", "SUDO_PASSWORD_PROMPT: ")
		//err = session.Setenv("PS4", "- ${LINENO}/${#BASH_SOURCE}: ")
		//if err != nil {
		//	log.Println(err)
		//}
		stdin, _ := session.StdinPipe()
		stdout, _ := session.StdoutPipe()
		//stderr, _ := session.StderrPipe() // never used, so maybe setup a fifo?

		// Read the input from the reader and print it to the screen
		handler := func(input io.Reader, fd int, c chan bool, iHost int) {
			defer func() { c <- true }()
			buff := new(bytes.Buffer)
			rdr := make([]byte, 32<<10)
			var curStyle = new(ansi.StyledText)
			var doChomp bool
			for n, err := input.Read(rdr); n > 0 || err == nil; n, err = input.Read(rdr) {
				//fmt.Printf("read"+num+" %s\n", string(rdr[:n]))
				buff.Write(rdr[:n])
				for {
					str, err := buff.ReadString('\n')
					if doChomp && strings.TrimSpace(str) == "" {
						doChomp = false
						continue
					}
					if passwordRegex.Match([]byte(str)) {
						fmt.Fprintf(stdin, "%s\n", pass())
						if *debug {
							fmt.Println(s(ansi.String([]*ansi.StyledText{
								&ansi.StyledText{Label: host, FgCol: hostColor, BgCol: hostBgColor, Style: hostStyle},
								&ansi.StyledText{Label: " < sent password to sudo prompt---"},
							})))
						}
						doChomp = true
						str = ""
					}
					if passcodeRegex.Match([]byte(str)) {
						fmt.Fprintf(stdin, "%s\n", code())
						if *debug {
							fmt.Println(s(ansi.String([]*ansi.StyledText{
								&ansi.StyledText{Label: host, FgCol: hostColor, BgCol: hostBgColor, Style: hostStyle},
								&ansi.StyledText{Label: " < sent pass CODE to sudo prompt---"},
							})))
						}
						doChomp = true
						str = ""
					}
					if err == nil {
						// Parse the string to gleen text style for printing
						styledText, _ := ansi.Parse(
							strings.TrimSuffix(ansi.String([]*ansi.StyledText{curStyle}), "\033[0m")+str,
							ansi.WithIgnoreInvalidCodes())
						styledText = chopCarriageReturn(styledText)
						if len(styledText) > 0 {
							styledText[len(styledText)-1].Label = strings.TrimSuffix(styledText[len(styledText)-1].Label, "\n")
							fmt.Printf("%s\n", s(ansi.String(append(
								[]*ansi.StyledText{
									&ansi.StyledText{Label: host + " |", FgCol: hostColor, BgCol: hostBgColor, Style: hostStyle},
									//				&ansi.StyledText{Label: " |"},
								}, styledText...))))

							// Save current style
							curStyle = styledText[len(styledText)-1]
							curStyle.Label = ""
							lineCounts[iHost]++
						}
					} else {
						// This may be a partial line, put it back in the buffer and break the loop
						buff.Write([]byte(str))
						break
					}
				}
			}
		}

		a := make(chan bool)
		//a, b := make(chan bool), make(chan bool)
		go handler(stdout, 1, a, iHost)
		//go handler(stderr, 2, b)

		var cmdLine string
		if *script == "" {
			if *command != "" {
				cmdLine = *shell + " -c " + shellescape.Quote(*command) + " " + scriptArgs
			} else {
				cmdLine = scriptArgs
			}
		} else {
			if *debug {
				cmdLine = "PS4='#${LINENO} \\w> ' " + *shell + " -x " + tempFull + " " + scriptArgs
			} else {
				cmdLine = *shell + " " + tempFull + " " + scriptArgs
			}
		}
		if *debug {
			fmt.Println(s(ansi.String([]*ansi.StyledText{
				&ansi.StyledText{Label: host + " > ", FgCol: hostColor, BgCol: hostBgColor, Style: hostStyle},
				&ansi.StyledText{Label: cmdLine}})))
		}

		session.Start(cmdLine)
		err = session.Wait()
		<-a
		if err != nil {
			if exitStatus, ok := err.(*ssh.ExitError); ok {
				exitCodes[iHost] = exitStatus.ExitStatus()
			}
		}
		//<-b
	}

	/*
	 * SSH session for clean up after running the script
	 */

	for _, dst := range dstFullName {
		session, err := client.NewSession()
		if err != nil {
			return err
		}
		err = session.Run("/usr/bin/rm " + dst)
		session.Close()
		if err != nil {
			session, err := client.NewSession()
			if err == nil {
				session.Run("/bin/rm " + dst)
				session.Close()
			}
		}
	}
	//fmt.Println("returning")
	return nil
}

// Generate a temp file name
func TempFileName(prefix, suffix string) (full, short string) {
	randBytes := make([]byte, 16)
	rand.Read(randBytes)
	return filepath.Join(os.TempDir(), prefix+hex.EncodeToString(randBytes)+suffix), prefix + hex.EncodeToString(randBytes) + suffix
}

func chopCarriageReturn(in []*ansi.StyledText) []*ansi.StyledText {
	if len(in) == 0 {
		return in
	}
	last := in[len(in)-1]
	if strings.HasSuffix(last.Label, "\r\n") {
		last.Label = strings.TrimSuffix(last.Label, "\r\n") + "\n"
	}
	for i := len(in) - 1; i >= 0; i-- {
		if j := strings.LastIndexByte(in[i].Label, '\r'); j >= 0 {
			//if l := len(in[i].Label); l-2 == j && in[i].Label[l-1] == '\n' {
			//	return in
			//}
			//fmt.Printf("%q", in[i].Label, j)
			in[i].Label = in[i].Label[j+1:]
			if len(in[i].Label) == 0 {
				//if i == len(in)-1 {
				//	return nil
				//}
				return in[i+1:]
			}
			return in[i:]
		}
	}
	return in
}

func getColour(i int) (fg *ansi.Col, bg *ansi.Col, style ansi.TextStyle) {
	i = i % 9
	if i < 2 {
		return ansi.Cols[i+2], bg, 0
	} else if i < 4 {
		return ansi.Cols[i+3], bg, 0
	}
	return ansi.Cols[i-4+2], bg, 1
}

func s(str string) string {
	if *disableColors {
		if nc, err := ansi.Cleanse(str); err == nil {
			return nc
		}
	}
	return str
}
