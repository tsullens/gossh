package gosshclient

import (
  "golang.org/x/crypto/ssh"
  "golang.org/x/crypto/ssh/agent"
  "golang.org/x/crypto/ssh/knownhosts"
  "golang.org/x/crypto/ssh/terminal"
  "runtime"
  "fmt"
  "os"
  "time"
  "syscall"
  "strings"
  "io/ioutil"
  "net"
)

const TERM_CYAN = "\x1b[0;36m"
const TERM_GREEN = "\x1b[0;32m"
const TERM_YELLOW = "\x1b[0;33m"
const TERM_CLEAR = "\033[0m"

type GosshClient struct {
  handler        executor
  serverList     ServerList
  routines       int
  port           int
  clientConfig   *ssh.ClientConfig
  sudo           bool
  agent          agent.Agent
  user           string
}

func NewGosshClient(servers ServerList) (*GosshClient) {
  return &GosshClient{
    serverList: servers,
    routines:   runtime.NumCPU(),
    port:         22,
    sudo:         false,
    agent:        nil,
    user:         os.Getenv("USER"),
  }
}

func (c *GosshClient) ClientConfig(conf *ssh.ClientConfig) {
  c.clientConfig = conf
}

func (c *GosshClient) Agent(agent agent.Agent) {
  c.agent = agent
}

func (c *GosshClient) Sudo() {
  c.sudo = true
}

func (c *GosshClient) Routines(num int) {
  c.routines = num
}

func (c *GosshClient) User(u string) {
  c.user = u
}

func (c *GosshClient) Port(p int) {
  c.port = p
}

func (client *GosshClient) ExecuteCommands(commands []string) ([]*ClientResponse, error) {
  err := client.initClientConfig()
  if err != nil {
    return nil, err
  }
  client.handler = newCommandExecutor(commands, client.port, client.clientConfig, client.sudo, client.agent, client.user)
  return client.execute()
}

func (client *GosshClient) ExecuteScript(scriptArg string) ([]*ClientResponse, error) {
  var err error
  err = client.initClientConfig()
  if err != nil {
    return nil, err
  }
  client.handler, err = newScriptExecutor(scriptArg, client.port, client.clientConfig, client.sudo, client.agent, client.user)
  if err != nil {
    return nil, err
  }
  return client.execute()
}

func (client *GosshClient) execute() ([]*ClientResponse, error) {

  var results []*ClientResponse

  serverChan := make(chan string, len(client.serverList))
  responseChan := make(chan *ClientResponse, len(client.serverList))
  for i := 0; i < client.routines; i++ {
    go client.handler.run(serverChan, responseChan)
  }
  go func() {
    for _, host := range client.serverList {
      serverChan <- host
    }
    close(serverChan)
  }()

  // Really don't know that this is the idiomatic way to do this.
  // Maybe need to think of a better way to handle this whole section of code
  for i := 0; i < len(client.serverList); i++ {
    select {
    case result := <- responseChan:
      results = append(results, result)
    }
  }
  return results, nil
}

/*
  "Execution-time" loading of SSH config, if one hasn't been provided for us.
*/
func (client *GosshClient) initClientConfig() (error) {
  if client.clientConfig != nil {
    // ssh.CLientConfig has been provided for us
    return nil
  }
  hostKeyCallback, err := knownhosts.New(fmt.Sprintf("%s/.ssh/known_hosts", os.Getenv("HOME")))
  if err != nil {
    return err
  }
  if client.agent == nil {
    agent, err := sshAgent()
    if err != nil {
      return err
    }
    client.agent = agent
  }
  sshAuthMethods := make([]ssh.AuthMethod, 0)
  if client.agent != nil {
    sshAuthMethods = append(sshAuthMethods, ssh.PublicKeysCallback(client.agent.Signers))
  }
  sshAuthMethods = append(sshAuthMethods, ssh.PublicKeysCallback(client.agent.Signers))
  signer, err := getPrivateKey(fmt.Sprintf("%s/.ssh/id_rsa", os.Getenv("HOME")))
  if signer != nil {
    sshAuthMethods = append(sshAuthMethods, ssh.PublicKeys(signer))
  } else {
    // No id_rsa found, force use of password Auth
    password, err := passwordPrompt()
    if err != nil {
      return err
    }
    sshAuthMethods = append(sshAuthMethods, ssh.PasswordCallback(passwordCallback(password)))
  }
  client.clientConfig = &ssh.ClientConfig{
    User:             client.user,
    Auth:             sshAuthMethods,
    HostKeyCallback:  hostKeyCallback,
    Timeout:          time.Duration(int64(time.Second * 20)),
  }
  return nil
}

type ClientResponse struct {
  Host          string
  ResponseData  string
}

func (cr *ClientResponse) String() (string) {
  return fmt.Sprintf("Host: %s%s%s\n%s\n--------------------------------\n", TERM_GREEN, cr.Host, TERM_CLEAR, cr.ResponseData)
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

func passwordPrompt() (string, error) {
  fmt.Print("Password: ")
  password, err := terminal.ReadPassword(int(syscall.Stdin))
  fmt.Println()
  if err != nil {
    return "", err
  }
  return strings.TrimSpace(string(password)), nil
}
// Callback Method: returns a func to be used in a Callback.
func passwordCallback(password string) (func() (string, error)) {
  return func() (string, error) {
    return password, nil
  }
}

// This is kinda a hacky method right now. There's two cases we want to use this:
// 1. To check if an id_rsa exists & is usable: we don't want to Fatal
// 2. If a specific keyfile is passed as an arg we want to Fatal if we can't use it.
func getPrivateKey(identityFile string) (ssh.Signer, error) {
  key, err := ioutil.ReadFile(identityFile)
  if err != nil {
    return nil, err
  }
  signer, err := ssh.ParsePrivateKey(key)
  if err != nil {
    return nil, err
  }
  return signer, nil
}

func sshAgent() (agent.Agent, error) {
  authSock, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
  if err != nil {
    return nil, err
  }
  return agent.NewClient(authSock), nil
}
