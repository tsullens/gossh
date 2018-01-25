package gossh

import (
  "golang.org/x/crypto/ssh"
  "github.com/tmc/scp"
  "crypto/sha256"
  "encoding/hex"
  "fmt"
  "io"
  "io/ioutil"
  "bytes"
  "os"
  "path/filepath"
  "strings"
  "errors"
)

type executor interface {
  run(<-chan string, chan<- *ClientResponse)
}

type commandExecutor struct {
  port           int
  clientConfig   *ssh.ClientConfig
  commands       []string
  proxyHost      string
}

type scriptExecutor struct {
  port           int
  clientConfig   *ssh.ClientConfig
  sudo           bool
  fileSize       int64
  fileReader     io.Reader
  fileNameTmp    string
  scriptCmd      string
  proxyHost      string
}

func newCommandExecutor(args []string, port int, clientConfig *ssh.ClientConfig, sudo bool, proxyHost string) (*commandExecutor) {
  if sudo {
    for i, cmd := range args {
      args[i] = fmt.Sprintf("sudo %s", cmd)
    }
  }
  return &commandExecutor{
    port:         port,
    clientConfig: clientConfig,
    commands:     args,
    proxyHost:    proxyHost,
  }
}

func newScriptExecutor(arg string, port int, clientConfig *ssh.ClientConfig, sudo bool, proxyHost string) (*scriptExecutor, error) {

  var (
    cmd string
    file string
    err error
  )
  switch args := strings.Split(arg, ":"); len(args) {
  case 1:
    file = args[0]
  case 2:
    cmd = args[0]
    file = args[1]
  default:
    return nil, errors.New("Failed to parse Script argument.")
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

  return &scriptExecutor{
    port:          port,
    clientConfig:  clientConfig,
    sudo:          sudo,
    fileSize:      s.Size(),
    fileReader:    bytes.NewBuffer(buf),
    fileNameTmp:   hex.EncodeToString(fileSum[:]),
    scriptCmd:     cmd,
    proxyHost:     proxyHost,
  }, nil
}

func (exec *commandExecutor) run(serverChan <-chan string, responseChan chan<- *ClientResponse) {
  var (
    client, proxyClient *ssh.Client
    err error
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

    // Set up our proxy session
    if exec.proxyHost != "" {
      conn, err := proxyClient.Dial("tcp", fmt.Sprintf("%s:%d", host, exec.port))
      if err != nil {
        response.addResponseData(fmt.Sprintf("Failed to connect to host %s: %s", host, err.Error()))
        responseChan <- response
        continue
      }
      c, nc, rc, err := ssh.NewClientConn(conn, fmt.Sprintf("%s:%d", host, exec.port), exec.clientConfig)
      if err != nil {
        response.addResponseData(fmt.Sprintf("Failed to establish client connection for host %s: %s", host, err.Error()))
        responseChan <- response
        continue
      }
      client = ssh.NewClient(c, nc, rc)
    } else {
      // Create our SSH client for this host
      client, err = ssh.Dial("tcp", fmt.Sprintf("%s:%d", host, exec.port), exec.clientConfig)
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
      response.addResponseData(fmt.Sprintf("%s%s%s", TERM_YELLOW, cmd, TERM_CLEAR))
      response.addResponseData(fmt.Sprintf("%s%s%s", TERM_CYAN, strings.TrimSpace(string(cmdOut)), TERM_CLEAR))
    } // range: commands
    // Last we send our response (ClientResponse) struct to our main routine.
    responseChan <- response
    // range: host
  }
}

func (exec *scriptExecutor) run(serverChan <-chan string, responseChan chan<- *ClientResponse) {
  remoteDir := "/tmp"
  var (
    session *ssh.Session
    cmdOut []byte
    client *ssh.Client
    scriptCmd string
    err error
  )
  if exec.scriptCmd == "" {
    scriptCmd = fmt.Sprintf("%s/%s", remoteDir, exec.fileNameTmp)
  } else {
    scriptCmd = fmt.Sprintf("%s %s/%s", exec.scriptCmd, remoteDir, exec.fileNameTmp)
  }
  if exec.sudo {
    scriptCmd = fmt.Sprintf("sudo %s", scriptCmd)
  }

  /*
    We range over "jobs" (hosts) in the JobChannel channel and pull each off to
    run
  */
  for host := range serverChan {
    // initiate our response struct
    response := &ClientResponse{
      Host: host,
    }
    // Create our SSH client for this host
    client, err = ssh.Dial("tcp", fmt.Sprintf("%s:%d", host, exec.port), exec.clientConfig)
    if err != nil {
      response.addResponseData(fmt.Sprintf("Failed to connect & run script: %s", err.Error()))
      responseChan <- response
      continue
    }
    /*
      Session block for copying script file to host
    */
    session, err = client.NewSession()
    if err != nil {
      response.addResponseData(fmt.Sprintf("Failed to create session: %s", err.Error()))
      responseChan <- response
      continue
    }
    defer session.Close()
    err = scp.Copy(exec.fileSize, os.FileMode(0755), exec.fileNameTmp, exec.fileReader, remoteDir, session)
    if err != nil {
      response.addResponseData(fmt.Sprintf("Failed to copy script: %s", err.Error()))
      responseChan <- response
      continue
    }
    session.Close()

    /*
      Session block to execute our Script / scriptCmd against the host
    */
    session, err = client.NewSession()
    if err != nil {
      response.addResponseData(fmt.Sprintf("Failed to create session: %s", err.Error()))
      responseChan <- response
      continue
    }
    cmdOut, err = session.CombinedOutput(scriptCmd)
    if err != nil {
      response.addResponseData(fmt.Sprintf("Failed to run script: %s", err.Error()))
      responseChan <- response
      continue
    }
    response.addResponseData(fmt.Sprintf("%s%s%s", TERM_YELLOW, scriptCmd, TERM_CLEAR))
    response.addResponseData(fmt.Sprintf("%s%s%s", TERM_CYAN, string(cmdOut), TERM_CLEAR))
    session.Close()

    /*
      Session to cleanup / remove the Script file
    */
    session, err = client.NewSession()
    if err != nil {
      response.addResponseData(fmt.Sprintf("Failed to create session: %s", err.Error()))
      responseChan <- response
      continue
    }
    cmdOut, err = session.CombinedOutput(fmt.Sprintf("rm -f %s/%s", remoteDir, exec.fileNameTmp))
    if err != nil {
      response.addResponseData(fmt.Sprintf("Failed to remove script: %s", err.Error()))
      responseChan <- response
      continue
    }
    // Last we send our response (ClientResponse) struct to our main routine.
    responseChan <- response
  }
}
