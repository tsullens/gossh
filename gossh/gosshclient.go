// Package gossh implements a custom ssh client intended for parallel execution
// against many hosts. It leverages the golang ssh package, golang.org/x/crypto/ssh,
// but provides a higher-level interface to allow users to run commands or scripts
// against numerous hosts over ssh and in parallel.
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

const (
  TERM_CYAN = "\x1b[0;36m"    // Terminal coloring for response output
  TERM_GREEN = "\x1b[0;32m"
  TERM_YELLOW = "\x1b[0;33m"
  TERM_CLEAR = "\033[0m"
  REMOTE_SCRIPT_DIR = "/tmp"  // Directory on remote servers to copy a script to
)

type GosshClient struct {
  handler        executor
  serverList     ServerList
  port           int
  routines       int
  clientConfig   *ssh.ClientConfig
  sudo           bool
  agent          agent.Agent
  user           string
  proxyHost      string
}

// Creates a default GosshClient.
// Functions are provided to customize the GosshClient, and are allowed to be chained.
func NewGosshClient(servers ServerList) (*GosshClient) {
  return &GosshClient{
    serverList:   servers,
    port:         22,
    routines:     runtime.NumCPU(),
    sudo:         false,
    agent:        nil,
  }
}
// Provide a custom SSH ClientConfig to use.
// By default the client sets up a typical SSH configuration, but if a custom
// one is provided via this func the Client will use that.
// We pass by value here so that the ClientConfig stays internal to the GosshClient
func (c *GosshClient) ClientConfig(conf ssh.ClientConfig) (*GosshClient) {
  c.clientConfig = &conf
  return c
}
// Provide a custom SSH agent to use.
// This will only be used if a custom ssh.ClientConfig is not provided.
func (c *GosshClient) Agent(agent agent.Agent) {
  c.agent = agent
}
// Execute commands with sudo on remote servers.
// Default is false.
func (c *GosshClient) Sudo() (*GosshClient) {
  c.sudo = true
  return c
}
// Number of parallel routines to use (i.e. thread pool).
// Default is the number of processors at runtime.
func (c *GosshClient) Routines(num int) (*GosshClient) {
  c.routines = num
  return c
}
// Specify user to connect as.
// Default is to use current user.
func (c *GosshClient) User(u string) (*GosshClient) {
  c.user = u
  return c
}
// Specify port to use for host connections.
// Default is 22.
func (c *GosshClient) Port(p int) (*GosshClient) {
  c.port = p
  return c
}
// Use provided proxy config for SSH connections.
// host can be in the form host:port, and if not we will assume port 22 to be used.
func (c *GosshClient) ProxyHost(host string) (*GosshClient) {
  _h := strings.SplitN(host, ":", 2)
  if len(_h) == 1 {
    host = fmt.Sprintf("%s:%d", host, 22)
  }
  c.proxyHost = host
  return c
}

// Execute the array of commands against our hosts.
func (c *GosshClient) ExecuteCommands(commands []string) ([]*ClientResponse, error) {
  err := c.initClientConfig()
  if err != nil {
    return nil, err
  }
  c.handler = newCommandExecutor(commands, c.clientConfig, c.sudo, c.proxyHost)
  return c.execute()
}

// Execute a script, full path provided as a string argument, on all hosts.
func (c *GosshClient) ExecuteScript(scriptArg string) ([]*ClientResponse, error) {
  var err error
  err = c.initClientConfig()
  if err != nil {
    return nil, err
  }
  c.handler, err = newScriptExecutor(scriptArg, c.clientConfig, c.sudo, c.proxyHost)
  if err != nil {
    return nil, err
  }
  return c.execute()
}

func (c *GosshClient) execute() ([]*ClientResponse, error) {

  var results []*ClientResponse

  serverChan := make(chan string, len(c.serverList))
  responseChan := make(chan *ClientResponse, len(c.serverList))
  for i := 0; i < c.routines; i++ {
    go c.handler.run(serverChan, responseChan)
  }
  go func() {
    for _, host := range c.serverList {
      serverChan <- fmt.Sprintf("%s:%d", host, c.port)
    }
    close(serverChan)
  }()

  // Really don't know that this is the idiomatic way to do this.
  // Maybe need to think of a better way to handle this whole section of code
  for i := 0; i < len(c.serverList); i++ {
    select {
    case result := <- responseChan:
      results = append(results, result)
    }
  }
  return results, nil
}

// "Execution-time" loading of SSH config, if one hasn't been provided for us.
func (c *GosshClient) initClientConfig() (error) {
  if c.clientConfig != nil {
    // ssh.CLientConfig has been provided for us
    return nil
  }
  hostKeyCallback, err := knownhosts.New(fmt.Sprintf("%s/.ssh/known_hosts", os.Getenv("HOME")))
  if err != nil {
    return err
  }
  sshAuthMethods := []ssh.AuthMethod{AgentAuth(), PublicKeyAuth(), PasswordAuth()}
  if c.agent != nil {
    sshAuthMethods = append(sshAuthMethods, ssh.PublicKeysCallback(c.agent.Signers))
  }
  c.clientConfig = &ssh.ClientConfig{
    User:             c.user,
    Auth:             sshAuthMethods,
    HostKeyCallback:  hostKeyCallback,
    Timeout:          time.Duration(int64(time.Second * 20)),
  }
  return nil
}
