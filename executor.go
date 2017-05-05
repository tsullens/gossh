package main

import (
  "golang.org/x/crypto/ssh"
  "github.com/tmc/scp"
  "crypto/sha256"
  "encoding/hex"
  "sync"
  "fmt"
  "io"
  "io/ioutil"
  "bytes"
  "os"
  "path/filepath"
  "strings"
  "errors"
)

type Executor interface {
  Run(wg sync.WaitGroup)
}

type CommandExecutor struct {
  Commands        []string
  JobChannel      chan string
  ResponseChannel chan ExecutorResponse
}

type ScriptExecutor struct {
  FileSize        int64
  FileReader      io.Reader
  FileNameTmp     string
  ScriptCmd       string
  JobChannel      chan string
  ResponseChannel chan ExecutorResponse
}

/*
  This struct is used in main() but not here
  Might just get rid of it.
*/
type ExecutorCom struct {
  JobChannel       chan string
  ResponseChannel  chan ExecutorResponse
}

type ExecutorResponse struct {
  Host          string
  ResponseData  string
}
func (r *ExecutorResponse) addResponseData(data string) {
  r.ResponseData = fmt.Sprintf("%s\n%s", r.ResponseData, data)
}

func NewCommandExecutor(args []string, com *ExecutorCom) (*CommandExecutor) {
  return &CommandExecutor{
    Commands:         args,
    JobChannel:       com.JobChannel,
    ResponseChannel:  com.ResponseChannel,
  }
}

func NewScriptExecutor(arg string, com *ExecutorCom) (*ScriptExecutor, error) {

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

  return &ScriptExecutor{
    FileSize:       s.Size(),
    FileReader:     bytes.NewBuffer(buf),
    FileNameTmp:    hex.EncodeToString(fileSum[:]),
    ScriptCmd:      cmd,
    //ComChannel:   com,
    JobChannel:     com.JobChannel,
    ResponseChannel:  com.ResponseChannel,
  }, nil
}

func (exec *CommandExecutor) Run(wg sync.WaitGroup) {
  defer wg.Done()
  Config.logVerbose("Started CommandExecutor goroutine")
  /*
    We range over "jobs" (hosts) in the JobChannel channel and pull each off to
    run
  */
  for host := range exec.JobChannel {
    Config.logVerbose(fmt.Sprintf("Started run of host %s", host))

    // initiate our response struct
    response := &ExecutorResponse{
      Host: host,
    }
    // Create our SSH client for this host
    client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", host, Config.SSHPort), Config.SSHClientConfig)
    if err != nil {
      response.addResponseData(fmt.Sprintf("Failed to connect: %s", err.Error()))
      exec.ResponseChannel <- *response
      continue
    }
    Config.logVerbose(fmt.Sprintf("Connected to host %s", host))
    /*
      We iterate over all over our commands and execute each of them
    */
    for _, cmd := range exec.Commands {
      if Config.Sudo {
        cmd = fmt.Sprintf("sudo %s", cmd)
      }
      Config.logVerbose(fmt.Sprintf("Running command %s on host %s", cmd, host))

      session, err := client.NewSession()
      if err != nil {
        response.addResponseData(fmt.Sprintf("Failed to create session: %s", err.Error()))
        exec.ResponseChannel <- *response
        continue
      }
      defer session.Close()

      cmdOut, err := session.CombinedOutput(cmd)
      if err != nil {
          response.addResponseData(fmt.Sprintf("Failed to run cmd (%s): %s", cmd, err.Error()))
          exec.ResponseChannel <- *response
          continue
      }
      response.addResponseData(fmt.Sprintf("%s%s%s", TERM_YELLOW, cmd, TERM_CLEAR))
      response.addResponseData(fmt.Sprintf("%s%s%s", TERM_CYAN, string(cmdOut), TERM_CLEAR))
    }
    // Last we send our response (ExecutorResponse) struct to our main routine.
    Config.logVerbose(fmt.Sprintf("Sending host %s response", host))
    exec.ResponseChannel <- *response
  }
}

func (exec *ScriptExecutor) Run(wg sync.WaitGroup) {
  defer wg.Done()

  remoteDir := "/tmp"
  var (
    session *ssh.Session
    cmdOut []byte
    client *ssh.Client
    scriptCmd string
    err error
  )
  if exec.ScriptCmd == "" {
    scriptCmd = fmt.Sprintf("%s/%s", remoteDir, exec.FileNameTmp)
  } else {
    scriptCmd = fmt.Sprintf("%s %s/%s", exec.ScriptCmd, remoteDir, exec.FileNameTmp)
  }
  if Config.Sudo {
    scriptCmd = fmt.Sprintf("sudo %s", scriptCmd)
  }

  /*
    We range over "jobs" (hosts) in the JobChannel channel and pull each off to
    run
  */
  for host := range exec.JobChannel {
    // initiate our response struct
    response := &ExecutorResponse{
      Host: host,
    }
    // Create our SSH client for this host
    client, err = ssh.Dial("tcp", fmt.Sprintf("%s:%d", host, Config.SSHPort), Config.SSHClientConfig)
    if err != nil {
      response.addResponseData(fmt.Sprintf("Failed to connect & run script: %s", err.Error()))
      exec.ResponseChannel <- *response
      continue
    }
    /*
      Session block for copying script file to host
    */
    session, err = client.NewSession()
    if err != nil {
      response.addResponseData(fmt.Sprintf("Failed to create session: %s", err.Error()))
      exec.ResponseChannel <- *response
      continue
    }
    defer session.Close()
    Config.logVerbose(fmt.Sprintf("SSH Session to %s established, copying script: %s", host, exec.FileNameTmp))
    err = scp.Copy(exec.FileSize, os.FileMode(0755), exec.FileNameTmp, exec.FileReader, remoteDir, session)
    if err != nil {
      response.addResponseData(fmt.Sprintf("Failed to copy script: %s", err.Error()))
      exec.ResponseChannel <- *response
      continue
    }
    session.Close()

    /*
      Session block to execute our Script / scriptCmd against the host
    */
    session, err = client.NewSession()
    if err != nil {
      response.addResponseData(fmt.Sprintf("Failed to create session: %s", err.Error()))
      exec.ResponseChannel <- *response
      continue
    }
    cmdOut, err = session.CombinedOutput(scriptCmd)
    if err != nil {
      response.addResponseData(fmt.Sprintf("Failed to run script: %s", err.Error()))
      exec.ResponseChannel <- *response
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
      exec.ResponseChannel <- *response
      continue
    }
    cmdOut, err = session.CombinedOutput(fmt.Sprintf("rm -f %s/%s", remoteDir, exec.FileNameTmp))
    if err != nil {
      response.addResponseData(fmt.Sprintf("Failed to remove script: %s", err.Error()))
      exec.ResponseChannel <- *response
      continue
    }
    // Last we send our response (ExecutorResponse) struct to our main routine.
    exec.ResponseChannel <- *response
  }
}
