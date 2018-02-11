// Package gossh implements a custom ssh client intended for parallel execution
// against many hosts. It leverages the golang ssh package, golang.org/x/crypto/ssh,
// but provides a higher-level interface to allow users to run commands or scripts
// against numerous hosts over ssh and in parallel.
package gossh

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

const (
	termCyan        = "\x1b[0;36m"
	termGreen       = "\x1b[0;32m"
	termYellow      = "\x1b[0;33m"
	termClear       = "\033[0m"
	remoteScriptDir = "/tmp"
)

// A Client represents the parallel execution process.
type Client struct {
	handler      executor
	serverList   ServerList
	port         int
	routines     int
	clientConfig *ssh.ClientConfig
	sudo         bool
	agent        agent.Agent
	user         string
	proxyHost    string
}

// NewClient creates a new Client object.
// Functions are provided to customize the Client, and are allowed to be chained.
func NewClient(servers ServerList) *Client {
	return &Client{
		serverList: servers,
		port:       22,
		routines:   runtime.NumCPU(),
		sudo:       false,
		agent:      nil,
	}
}

// ClientConfig allows a custom ssh.ClientConfig to be provided.
// By default the client sets up a typical SSH configuration, but if a custom
// one is provided via this func the Client will use that.
// We pass by value here so that the ClientConfig stays internal to the Client
func (c *Client) ClientConfig(conf ssh.ClientConfig) *Client {
	c.clientConfig = &conf
	return c
}

// Agent allows a custom agent.Agent to be provided.
// This will only be used if a custom ssh.ClientConfig is not provided.
func (c *Client) Agent(agent agent.Agent) {
	c.agent = agent
}

// Sudo sets the Client to run sudo during execution.
// Default is false.
func (c *Client) Sudo() *Client {
	c.sudo = true
	return c
}

// Routines specifies the number of executions to run in parallel.
// Default is the number of processors at runtime.
func (c *Client) Routines(num int) *Client {
	c.routines = num
	return c
}

// User specifies the user to connect as.
// Default is to use current user.
func (c *Client) User(u string) *Client {
	c.user = u
	return c
}

// Port specifies the port to connect to.
// Is used for all servers.
// Default is 22.
func (c *Client) Port(p int) *Client {
	c.port = p
	return c
}

// ProxyHost specifies a proxy/jump host to connect through for all servers.
// host can be in the form host:port, and if not we will assume port 22 to be used.
func (c *Client) ProxyHost(host string) *Client {
	_h := strings.SplitN(host, ":", 2)
	if len(_h) == 1 {
		host = fmt.Sprintf("%s:%d", host, 22)
	}
	c.proxyHost = host
	return c
}

// ExecuteCommands has the Client execute the given commands on all servers.
// Returns an []*ClientResponse containing response data from all servers.
func (c *Client) ExecuteCommands(commands []string) ([]*ClientResponse, error) {
	err := c.initClientConfig()
	if err != nil {
		return nil, err
	}
	c.handler = newCommandExecutor(commands, c.clientConfig, c.sudo, c.proxyHost)
	return c.execute()
}

// ExecuteScript has the Client execute the given script, provided as a string on all servers.
// Returns an []*ClientResponse containing response data from all servers.
func (c *Client) ExecuteScript(scriptArg string) ([]*ClientResponse, error) {
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

func (c *Client) execute() ([]*ClientResponse, error) {

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
		case result := <-responseChan:
			results = append(results, result)
		}
	}
	return results, nil
}

// "Execution-time" loading of SSH config, if one hasn't been provided for us.
func (c *Client) initClientConfig() error {
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
		User:            c.user,
		Auth:            sshAuthMethods,
		HostKeyCallback: hostKeyCallback,
		Timeout:         time.Duration(int64(time.Second * 20)),
	}
	return nil
}
