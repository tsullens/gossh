package gossh

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strings"
	"syscall"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/terminal"
)

// ClientResponse represents the response data from each host.
type ClientResponse struct {
	Host         string
	ResponseData string
}

func (cr *ClientResponse) String() string {
	return fmt.Sprintf("Host: %s%s%s\r%s\n--------------------------------", termGreen, cr.Host, termClear, cr.ResponseData)
}

func (cr *ClientResponse) addResponseData(data string) {
	cr.ResponseData = fmt.Sprintf("%s\n%s", cr.ResponseData, data)
}

// ServerList is a custom type to represent a list of servers.
type ServerList []string

// NewServerList takes a string of comma-separated hosts and returns a ServerList.
func NewServerList(arg string) (ServerList, error) {
	return strings.Split(arg, ","), nil
}

// PasswordAuth is a convenience function for using password auth (prompt) in the
// []ssh.AuthMethod param in a ssh.ClientConfig.
func PasswordAuth() ssh.AuthMethod {
	fmt.Print("Password: ")
	password, err := terminal.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		password = make([]byte, 0)
	}
	return ssh.Password(strings.TrimSpace(string(password)))
}

// PublicKeyAuth is a convenience function for using public key auth in the
// []ssh.AuthMethod param in a ssh.ClientConfig.
// 0 or more keyfiles can be provided as arguments, if 0 are given this will
// try to load the typical ~/.ssh/id_rsa for use.
func PublicKeyAuth(identityFiles ...string) ssh.AuthMethod {
	_ifiles := identityFiles
	if len(_ifiles) == 0 {
		_ifiles = []string{fmt.Sprintf("%s/.ssh/id_rsa", os.Getenv("HOME"))}
	}
	var signers []ssh.Signer
	for _, f := range _ifiles {
		key, err := ioutil.ReadFile(f)
		if err != nil {
			fmt.Printf("Warning: Identity file %s not accessible: %s\n", f, err.Error())
			continue
		}
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			fmt.Printf("Warning: Unable to parse Identity file %s: %s\n", f, err.Error())
			continue
		}
		signers = append(signers, signer)
	}
	return ssh.PublicKeys(signers...)
}

// AgentAuth is a convenience function for using SSH in the
// []ssh.AuthMethod param in a ssh.ClientConfig.
// This attempts to use the typical $SSH_AUTH_SOCK env var and any identities in it.
func AgentAuth() ssh.AuthMethod {
	authSock, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
	if err != nil {
		return nil
	}
	sshagent := agent.NewClient(authSock)
	return ssh.PublicKeysCallback(sshagent.Signers)
}
