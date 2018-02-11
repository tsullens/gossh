package gossh

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/tmc/scp"
	"golang.org/x/crypto/ssh"
)

type executor interface {
	run(<-chan string, chan<- *ClientResponse)
}

type commandExecutor struct {
	clientConfig *ssh.ClientConfig
	commands     []string
	proxyHost    string
}

type scriptExecutor struct {
	clientConfig *ssh.ClientConfig
	fileSize     int64
	fileReader   io.Reader
	fileNameTmp  string
	scriptCmd    string
	proxyHost    string
}

func newCommandExecutor(args []string, clientConfig *ssh.ClientConfig, sudo bool, proxyHost string) *commandExecutor {
	if sudo {
		for i, cmd := range args {
			args[i] = fmt.Sprintf("sudo %s", cmd)
		}
	}
	return &commandExecutor{
		clientConfig: clientConfig,
		commands:     args,
		proxyHost:    proxyHost,
	}
}

func newScriptExecutor(arg string, clientConfig *ssh.ClientConfig, sudo bool, proxyHost string) (*scriptExecutor, error) {
	var (
		cmd       string
		scriptCmd string
		file      string
		err       error
	)
	switch args := strings.SplitN(arg, ":", 2); len(args) {
	case 1:
		file = args[0]
	case 2:
		cmd = args[0]
		file = args[1]
	default:
		return nil, errors.New("failed to parse Script argument")
	}
	/*
	   Expand / sanitize the file.
	   This is here since an argument like python:~/script.py will not be
	   automatically expanded via the shell, os.Open will not expand it either
	   as it expects absolute paths.
	*/
	if file[:2] == "~/" {
		file = filepath.Join(os.Getenv("HOME"), file[2:])
	}
	/*
	   Open the file, store the content in a buffer that implements
	   the io.Reader interface, and return our ScriptExecutor struct
	*/
	f, err := os.Open(file)
	defer f.Close()
	if err != nil {
		return nil, err
	}
	buf, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}
	s, err := f.Stat()
	if err != nil {
		return nil, err
	}
	fileSum := sha256.Sum256([]byte(s.Name()))
	fileNameTmp := hex.EncodeToString(fileSum[:])

	if cmd == "" {
		scriptCmd = fmt.Sprintf("%s/%s", remoteScriptDir, fileNameTmp)
	} else {
		scriptCmd = fmt.Sprintf("%s %s/%s", cmd, remoteScriptDir, fileNameTmp)
	}
	if sudo {
		scriptCmd = fmt.Sprintf("sudo %s", cmd)
	}

	return &scriptExecutor{
		clientConfig: clientConfig,
		fileSize:     s.Size(),
		fileReader:   bytes.NewBuffer(buf),
		fileNameTmp:  fileNameTmp,
		scriptCmd:    scriptCmd,
		proxyHost:    proxyHost,
	}, nil
}

func (exec *commandExecutor) run(serverChan <-chan string, responseChan chan<- *ClientResponse) {
	var (
		client, proxyClient *ssh.Client
		err                 error
	)
	if exec.proxyHost != "" {
		proxyClient, err = ssh.Dial("tcp", exec.proxyHost, exec.clientConfig)
		if err != nil {
			response := &ClientResponse{
				Host:         exec.proxyHost,
				ResponseData: fmt.Sprintf("Failed to establish proxy connection: %s", err.Error()),
			}
			responseChan <- response
			return
		}
	}
	// We range over "jobs" (hosts) in the JobChannel channel and pull each off to run
	for host := range serverChan {
		// initiate our response struct
		response := &ClientResponse{
			Host: host,
		}

		// Set up our proxy session if it exists
		if exec.proxyHost != "" {
			conn, err := proxyClient.Dial("tcp", host)
			if err != nil {
				response.addResponseData(fmt.Sprintf("Failed to connect to host %s: %s", host, err.Error()))
				responseChan <- response
				continue
			}
			c, nc, rc, err := ssh.NewClientConn(conn, host, exec.clientConfig)
			if err != nil {
				response.addResponseData(fmt.Sprintf("Failed to establish client connection for host %s: %s", host, err.Error()))
				responseChan <- response
				continue
			}
			client = ssh.NewClient(c, nc, rc)
		} else {
			// Create our SSH client for this host
			client, err = ssh.Dial("tcp", host, exec.clientConfig)
			if err != nil {
				response.addResponseData(fmt.Sprintf("Failed to connect to host: %s", err.Error()))
				responseChan <- response
				continue
			}
		}
		// We iterate over all over our commands and execute each of them
		for _, cmd := range exec.commands {

			session, err := client.NewSession()
			if err != nil {
				response.addResponseData(fmt.Sprintf("Failed to create session: %s", err.Error()))
				responseChan <- response
				continue
			}
			defer session.Close()

			cmdOut, err := session.CombinedOutput(cmd)
			if err != nil {
				response.addResponseData(fmt.Sprintf("Failed to run cmd (%s): %s", cmd, err.Error()))
				responseChan <- response
				continue
			}
			response.addResponseData(fmt.Sprintf("%s%s%s", termYellow, cmd, termClear))
			response.addResponseData(fmt.Sprintf("%s%s%s", termCyan, strings.TrimSpace(string(cmdOut)), termClear))
		} // range: commands
		// Last we send our response (ClientResponse) struct to our main routine.
		responseChan <- response
		// range: host
	}
}

func (exec *scriptExecutor) run(serverChan <-chan string, responseChan chan<- *ClientResponse) {
	var (
		session             *ssh.Session
		cmdOut              []byte
		client, proxyClient *ssh.Client
		err                 error
	)

	if exec.proxyHost != "" {
		proxyClient, err = ssh.Dial("tcp", exec.proxyHost, exec.clientConfig)
		if err != nil {
			response := &ClientResponse{
				Host:         exec.proxyHost,
				ResponseData: fmt.Sprintf("Failed to establish proxy connection: %s", err.Error()),
			}
			responseChan <- response
			return
		}
	}

	// We range over "jobs" (hosts) in the JobChannel channel and pull each off to run
	for host := range serverChan {
		// initiate our response struct
		response := &ClientResponse{
			Host: host,
		}
		// Set up our proxy session if it exists
		if exec.proxyHost != "" {
			conn, err := proxyClient.Dial("tcp", host)
			if err != nil {
				response.addResponseData(fmt.Sprintf("Failed to connect to host %s: %s", host, err.Error()))
				responseChan <- response
				continue
			}
			c, nc, rc, err := ssh.NewClientConn(conn, host, exec.clientConfig)
			if err != nil {
				response.addResponseData(fmt.Sprintf("Failed to establish client connection for host %s: %s", host, err.Error()))
				responseChan <- response
				continue
			}
			client = ssh.NewClient(c, nc, rc)
		} else {
			// Create our SSH client for this host
			client, err = ssh.Dial("tcp", host, exec.clientConfig)
			if err != nil {
				response.addResponseData(fmt.Sprintf("Failed to connect to host: %s", err.Error()))
				responseChan <- response
				continue
			}
		}

		//  Session block for copying script file to host
		session, err = client.NewSession()
		if err != nil {
			response.addResponseData(fmt.Sprintf("Failed to create session: %s", err.Error()))
			responseChan <- response
			continue
		}
		defer session.Close()
		err = scp.Copy(exec.fileSize, os.FileMode(0755), exec.fileNameTmp, exec.fileReader, remoteScriptDir, session)
		if err != nil {
			response.addResponseData(fmt.Sprintf("Failed to copy script: %s", err.Error()))
			responseChan <- response
			continue
		}
		session.Close()

		//  Session block to execute our Script / scriptCmd against the host
		session, err = client.NewSession()
		if err != nil {
			response.addResponseData(fmt.Sprintf("Failed to create session: %s", err.Error()))
			responseChan <- response
			continue
		}
		cmdOut, err = session.CombinedOutput(exec.scriptCmd)
		if err != nil {
			response.addResponseData(fmt.Sprintf("Failed to run script: %s", err.Error()))
			responseChan <- response
			continue
		}
		response.addResponseData(fmt.Sprintf("%s%s%s", termYellow, exec.scriptCmd, termClear))
		response.addResponseData(fmt.Sprintf("%s%s%s", termCyan, strings.TrimSpace(string(cmdOut)), termClear))
		session.Close()

		//  Session to cleanup / remove the Script file
		session, err = client.NewSession()
		if err != nil {
			response.addResponseData(fmt.Sprintf("Failed to create session: %s", err.Error()))
			responseChan <- response
			continue
		}
		cmdOut, err = session.CombinedOutput(fmt.Sprintf("rm -f %s/%s", remoteScriptDir, exec.fileNameTmp))
		if err != nil {
			response.addResponseData(fmt.Sprintf("Failed to remove script: %s", err.Error()))
			responseChan <- response
			continue
		}
		// Last we send our response (ClientResponse) struct to our main routine.
		responseChan <- response
	}
}
