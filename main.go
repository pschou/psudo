package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	ansi "github.com/leaanthony/go-ansi-parser"
	"github.com/remeh/sizedwaitgroup"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var (
	userSetting         = flag.String("u", "", "Use this user rather than the current user")
	hostListFile        = flag.String("h", "", "Read hosts from given host file")
	hostListString      = flag.String("H", "", "List of hosts defined in a quoted string \"host1, host2\"")
	script              = flag.String("s", "", "Script to execute remotely")
	command             = flag.String("c", "", "Command to execute remotely")
	parallel            = flag.Int("p", 4, "Maximum concurrent connections allowed")
	identity            = flag.String("i", "", "SSH identity file for login, the private key for single use")
	disableAgent        = flag.Bool("A", false, "Disable SSH agent forwarding")
	debug               = flag.Bool("d", false, "Turn on script debugging")
	passwordMatch       = flag.String("pw", `^\[sudo\] password for `, "Send password for line matching")
	username, pass      string
	sshInteractiveTries int
	sshWorked           bool
	passwordRegex       *regexp.Regexp
	version             string
	shortList           []string
)

func main() {
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "Parallel Remote SUDO, Version", version, "(https://github.com/pschou/psudo)")
		fmt.Fprintln(os.Stderr, "Usage of "+os.Args[0]+":")
		flag.PrintDefaults()
	}
	flag.Parse()
	if (*hostListFile == "" && *hostListString == "") || (*script == "" && *command == "") {
		flag.Usage()
		os.Exit(1)
	}
	passwordRegex = regexp.MustCompile(*passwordMatch)

	// Host list from command line
	hostList := strings.FieldsFunc(*hostListString, func(c rune) bool {
		return c == ',' || c == ' '
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
	{ // Loop over hosts to verify that the TCP port is connectable
		var newHostList []string
		d := net.Dialer{Timeout: 3 * time.Second}
		for i, host := range hostList {
			if _, _, err := net.SplitHostPort(host); err != nil {
				host = net.JoinHostPort(host, "22")
				hostList[i] = host
			}
			conn, err := d.Dial("tcp", host)
			if err == nil {
				newHostList = append(newHostList, host)
				conn.Close()
			}
		}
		fmt.Println(len(newHostList), "hosts available out of", len(hostList), "loaded")
		hostList = newHostList
	}

	shortList = shorten(hostList)

	//fmt.Printf("%#v\n", hostList)
	if len(hostList) == 0 {
		return
	}

	// Prompt for credentials (for login and sudo)
	var err error
	username, pass, err = credentials()
	if err != nil {
		log.Fatal(err)
	}

	// Build configuration for ssh
	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(pass),
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

	var (
		checkPassed bool
		checkVerify = make(chan bool)
		swg         = sizedwaitgroup.New(*parallel)
	)

	for iHost, host := range hostList {
		swg.Add()
		go func(host string, iHost int) {
			fmt.Println(ansi.String([]*ansi.StyledText{&ansi.StyledText{
				Label: host + " -- Connecting", Style: ansi.Underlined, FgCol: getColour(iHost),
			}}))
			// Attempt connection into the first host
			client, err := ssh.Dial("tcp", host, config)
			if !checkPassed {
				checkVerify <- err == nil
			}
			if err != nil {
				log.Println(err)
				return
			}
			sshWorked = true

			defer client.Close()

			// Attempt initial send to one client
			err = sendScript(strings.TrimSuffix(shortList[iHost], ":22"), client, sshAgent, iHost)
			if err != nil {
				log.Println(host, err)
				return
			}
			swg.Done()
		}(host, iHost)

		// Wait for the first connection to succeed before continuing to the rest of the hosts
		if !checkPassed {
			checkPassed = <-checkVerify
			if !checkPassed {
				log.Fatal("error connecting to first host, verify credentials before proceeding")
			}
		}
	}
	swg.Wait()
}

// Send the script over the ssh connection
func sendScript(host string, client *ssh.Client, sshAgent *agent.ExtendedAgent, iHost int) error {
	tempFull, tempShort := TempFileName("psudo-", ".sh")
	/*
	 * SSH session for transferring the script
	 */
	if *script != "" {
		session, err := client.NewSession()
		if err != nil {
			return err
		}
		defer session.Close()

		file, err := os.Open(*script)
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()
		stat, err := file.Stat()
		if err != nil {
			log.Fatal(err)
		}

		file_sent := make(chan error, 1)
		go func() {
			hostIn, err := session.StdinPipe()
			if err != nil {
				file_sent <- err
			}
			defer hostIn.Close()
			fmt.Fprintf(hostIn, "C0600 %d %s\n", stat.Size(), tempShort)
			_, err = io.Copy(hostIn, file)
			if err != nil {
				file_sent <- err
			}
			fmt.Fprint(hostIn, "\x00")
			file_sent <- err
		}()

		session.Run("/usr/bin/scp -t /tmp/")

		err = <-file_sent
		if err != nil {
			log.Println(host, "Error writing file remotely:", err)
			return err
		}
		if *debug {
			fmt.Println(ansi.String([]*ansi.StyledText{
				&ansi.StyledText{Label: host + " <", FgCol: getColour(iHost)},
				&ansi.StyledText{Label: " Uploaded file to " + tempFull},
			}))
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
						fmt.Fprintf(stdin, "%s\n", pass)
						if *debug {
							fmt.Println(ansi.String([]*ansi.StyledText{
								&ansi.StyledText{Label: host, FgCol: getColour(iHost)},
								&ansi.StyledText{Label: " < sent password to sudo prompt---"},
							}))
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
							fmt.Printf("%s", ansi.String(append(
								[]*ansi.StyledText{
									&ansi.StyledText{Label: host + " |", FgCol: getColour(iHost)},
									//				&ansi.StyledText{Label: " |"},
								},
								chopCarriageReturn(styledText)...)))

							// Save current style
							curStyle = styledText[len(styledText)-1]
							curStyle.Label = ""
						}
					} else {
						// This may be a partial line, put it back in the buffer and break the loop
						buff.Write([]byte(str))
						break
					}
				}
			}
			c <- true
		}

		a := make(chan bool)
		//a, b := make(chan bool), make(chan bool)
		go handler(stdout, 1, a, iHost)
		//go handler(stderr, 2, b)

		var cmdLine string
		if *command != "" {
			if *debug {
				fmt.Println(ansi.String([]*ansi.StyledText{
					&ansi.StyledText{Label: host + " > ", FgCol: getColour(iHost)},
					&ansi.StyledText{Label: *command}}))
			}
			cmdLine = *command + ";"
		}
		if *script != "" {
			if *debug {
				cmdLine += "/bin/bash -c $'PS4=\\'#${LINENO} \\w> \\' /bin/bash -x " + tempFull + "'"
			} else {
				cmdLine += "/bin/bash " + tempFull
			}
		}

		session.Start(cmdLine)
		session.Wait()
		<-a
		//<-b
	}

	/*
	 * SSH session for clean up after running the script
	 */
	if *script != "" {
		session, err := client.NewSession()
		if err != nil {
			return err
		}
		defer session.Close()
		session.Run("/usr/bin/rm " + tempFull + " || /bin/rm " + tempFull)
	}
	//fmt.Println("returning")
	return nil
}

// Interactive login handler, answer a password question
func SshInteractive(user, instruction string, questions []string, echos []bool) (answers []string, err error) {
	sshInteractiveTries++
	if sshInteractiveTries > 1 && !sshWorked {
		log.Fatal("Bailing out early, password failed once")
	}
	answers = make([]string, len(questions))
	// The second parameter is unused
	for n, _ := range questions {
		answers[n] = pass
	}

	return answers, nil
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

func getColour(i int) *ansi.Col {
	return ansi.Cols[i%6+2]
}
