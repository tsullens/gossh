package gossh

import (
  "golang.org/x/crypto/ssh"
  "golang.org/x/crypto/ssh/agent"
  "golang.org/x/crypto/ssh/knownhosts"
  "runtime"
  "fmt"
  "os"
  "time"
  "strings"
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
  proxyHost      string
}

func NewGosshClient(servers ServerList) (*GosshClient) {
  return &GosshClient{
    serverList:   servers,
    routines:     runtime.NumCPU(),
    port:         22,
    sudo:         false,
    agent:        nil,
    user:         os.Getenv("USER"),
  }
}
// Provide a custom SSH ClientConfig to use.
// By default the client sets up a typical SSH configuration, but if a custom
// one is provided via this func the Client will use that.
func (c *GosshClient) ClientConfig(conf *ssh.ClientConfig) (*GosshClient) {
  c.clientConfig = conf
  return c
}
// Provide a custom SSH agent to use.
// This will only be used if a custom ClientConfig is not provided.
func (c *GosshClient) Agent(agent agent.Agent) {
  c.agent = agent
}
// Execute commands with sudo on remote servers.
func (c *GosshClient) Sudo() (*GosshClient) {
  c.sudo = true
  return c
}
// Number of parallel routines to use (i.e. thread pool)
func (c *GosshClient) Routines(num int) (*GosshClient) {
  c.routines = num
  return c
}
// Specify user to connect as. Default is to use current user.
func (c *GosshClient) User(u string) (*GosshClient) {
  c.user = u
  return c
}
// Specify non-default (22) SSH port to connect to
func (c *GosshClient) Port(p int) (*GosshClient) {
  c.port = p
  return c
}
// Use provided proxy config for SSH connections
// host can be in the form host:port, and if not we will assume port 22 to be used.
func (c *GosshClient) ProxyHost(host string) (*GosshClient) {
  _h := strings.SplitN(host, ":", 2)
  if len(_h) == 1 {
    host = fmt.Sprintf("%s:%d", host, 22)
  }
  c.proxyHost = host
  return c
}

func (client *GosshClient) ExecuteCommands(commands []string) ([]*ClientResponse, error) {
  err := client.initClientConfig()
  if err != nil {
    return nil, err
  }
  client.handler = newCommandExecutor(commands, client.port, client.clientConfig, client.sudo, client.proxyHost)
  return client.execute()
}

func (client *GosshClient) ExecuteScript(scriptArg string) ([]*ClientResponse, error) {
  var err error
  err = client.initClientConfig()
  if err != nil {
    return nil, err
  }
  client.handler, err = newScriptExecutor(scriptArg, client.port, client.clientConfig, client.sudo, client.proxyHost)
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
  sshAuthMethods := []ssh.AuthMethod{AgentAuth(), PublicKeyAuth(), PasswordAuth()}
  if client.agent != nil {
    sshAuthMethods = append(sshAuthMethods, ssh.PublicKeysCallback(client.agent.Signers))
  }
  client.clientConfig = &ssh.ClientConfig{
    User:             client.user,
    Auth:             sshAuthMethods,
    HostKeyCallback:  hostKeyCallback,
    Timeout:          time.Duration(int64(time.Second * 20)),
  }
  return nil
}
