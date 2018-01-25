package gossh

import (
  "golang.org/x/crypto/ssh"
  "golang.org/x/crypto/ssh/agent"
  "golang.org/x/crypto/ssh/terminal"
  "fmt"
  "os"
  "strings"
  "io/ioutil"
  "net"
  "syscall"
)

type ClientResponse struct {
  Host          string
  ResponseData  string
}

func (cr *ClientResponse) String() (string) {
  return fmt.Sprintf("Host: %s%s%s\r%s\n--------------------------------", TERM_GREEN, cr.Host, TERM_CLEAR, cr.ResponseData)
}

func (cr *ClientResponse) addResponseData(data string) {
  cr.ResponseData = fmt.Sprintf("%s\n%s", cr.ResponseData, data)
}

/*
  Custom type to represent a list of servers.
  This is intended to get more complex as I add the ability to provide
  regexes, etc.
*/
type ServerList []string
func NewServerList(arg string) (ServerList, error) {
  return strings.Split(arg, ","), nil
}

func PasswordAuth() (ssh.AuthMethod) {
  fmt.Print("Password: ")
  password, err := terminal.ReadPassword(int(syscall.Stdin))
  fmt.Println()
  if err != nil {
    password = make([]byte, 0)
  }
  return ssh.Password(strings.TrimSpace(string(password)))
}

func PublicKeyAuth(identityFiles ...string) (ssh.AuthMethod) {
  _ifiles := identityFiles
  if len(_ifiles) == 0 {
    _ifiles = []string{fmt.Sprintf("%s/.ssh/id_rsa", os.Getenv("HOME"))}
  }
  return ssh.PublicKeysCallback(func() ([]ssh.Signer, error) {
    var signers []ssh.Signer
    for _, f := range _ifiles {
      key, err := ioutil.ReadFile(f)
      if err != nil {
        fmt.Printf("Warning: Identity file %s not accessible: %s\n", f, err.Error())
        continue
      }
      signer, err := ssh.ParsePrivateKey(key)
      if err != nil {
        fmt.Printf("Warning: Unable to parse Identity file: %s\n", f, err.Error())
        continue
      }
      signers = append(signers, signer)
    }
    return signers, nil
  })
}

func AgentAuth() (ssh.AuthMethod) {
  authSock, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
  if err != nil {
    return nil
  }
  sshagent := agent.NewClient(authSock)
  return ssh.PublicKeysCallback(sshagent.Signers)
}
