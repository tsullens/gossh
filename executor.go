package main

import (
  "golang.org/x/crypto/ssh"
  "github.com/tmc/scp"
  "crypto/sha256"
  "encoding/hex"
  "sync"
  "fmt"
  "io"
  "os"
)

type Executor interface {
  Run(wg sync.WaitGroup)
}

type CommandExecutor struct {
  Commands    []string
//  ComChannel  *ExecutorCom
  Input       chan string
  Output      chan ExecutorResponse
}

type ScriptExecutor struct {
  FileSize      int64
  FileReader    io.Reader
  FileNameTmp   string
//  ComChannel    *ExecutorCom
  Input         chan string
  Output        chan ExecutorResponse
}

type ExecutorCom struct {
  Input   chan string
  Output  chan ExecutorResponse
}

type ExecutorResponse struct {
  //Id      Int
  Host    string
  Output  string
}

func NewCommandExecutor(cmds []string, com *ExecutorCom) (*CommandExecutor) {
  return &CommandExecutor{
    Commands:     cmds,
    //ComChannel:   com,
    Input:        com.Input,
    Output:       com.Output,
  }
}

func NewScriptExecutor(file string, com *ExecutorCom) (*ScriptExecutor, error) {
  f, err := os.Open(file)
  if err != nil {
    return nil, err
  }
  defer f.Close()
  s, err := f.Stat()
  if err != nil {
    return nil, err
  }
  fileSum := sha256.Sum256([]byte(s.Name()))

  return &ScriptExecutor{
    FileSize:     s.Size(),
    FileReader:   f,
    FileNameTmp:  hex.EncodeToString(fileSum[:]),
    //ComChannel:   com,
    Input:        com.Input,
    Output:       com.Output,
  }, nil
}

func (exec *CommandExecutor) Run(wg sync.WaitGroup) {
  defer wg.Done()
  if Config.Verbose {
    fmt.Printf("Started CommandExecutor goroutine\n")
  }

  for host := range exec.Input {
    if Config.Verbose {
      fmt.Printf("Started run of host %s\n", host)
    }
    client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", host, Config.SSHPort), Config.SSHClientConfig)
    if err != nil {
      exec.Output <- executorResponse(host, fmt.Sprintf("Failed to connect: %s", err.Error()))
      continue
    }

    for _, cmd := range exec.Commands {
      session, err := client.NewSession()
      if err != nil {
        //exec.Output <- fmt.Sprintf("host:%s\nFailed to create session: %s\n", host, err.Error())
        exec.Output <- executorResponse(host, fmt.Sprintf("Failed to create session: %s\n", host, err.Error()))
        continue
      }
      defer session.Close()
      cmdOut, err := session.CombinedOutput(cmd)
      if err != nil {
          //exec.Output <- fmt.Sprintf("host:%s\nFailed to run cmd (%s): %s", host, cmd, err.Error())
          exec.Output <- executorResponse(host, fmt.Sprintf("Failed to run cmd (%s): %s", host, cmd, err.Error()))
          continue
      }
      //exec.Output <- fmt.Sprintf("host:%s\n%s", cmdOut)
      exec.Output <- executorResponse(host, string(cmdOut))
    }
  }
}

func (exec *ScriptExecutor) Run(wg sync.WaitGroup) {
  defer wg.Done()
  remoteDir := "/tmp"
  var (
    session *ssh.Session
    cmdOut []byte
    client *ssh.Client
    err error
  )

  for host := range exec.Input {
    client, err = ssh.Dial("tcp", fmt.Sprintf("%s:%d", host, Config.SSHPort), Config.SSHClientConfig)
    if err != nil {
      //exec.Output <- fmt.Sprintf("host:%s\nFailed to connect & run script: %s\n", host, err.Error())
      exec.Output <- executorResponse(host, fmt.Sprintf("Failed to connect & run script: %s\n", host, err.Error()))
      continue
    }
    // Session for scp
    session, err = client.NewSession()
    if err != nil {
      //exec.Output <- fmt.Sprintf("host:%s\nFailed to create session: %s\n", host, err.Error())
      exec.Output <- executorResponse(host, fmt.Sprintf("Failed to create session: %s\n", host, err.Error()))
      continue
    }
    defer session.Close()
    if Config.Verbose {
      fmt.Printf("SSH Session to %s established, copying script: %s\n", host, exec.FileNameTmp)
    }
    err = scp.Copy(exec.FileSize, os.FileMode(0755), exec.FileNameTmp, exec.FileReader, remoteDir, session)
    if err != nil {
      //exec.Output <- fmt.Sprintf("host:%s\nFailed to copy script: %s\n", host, err.Error())
      exec.Output <- executorResponse(host, fmt.Sprintf("Failed to copy script: %s\n", err.Error()))
      continue
    }
    session.Close()
    //Session for shell command
    session, err = client.NewSession()
    if err != nil {
      //exec.Output <- fmt.Sprintf("host:%s\nFailed to create session: %s\n", host, err.Error())
      exec.Output <- executorResponse(host, fmt.Sprintf("Failed to create session: %s\n", host, err.Error()))
      continue
    }
    cmdOut, err = session.CombinedOutput(fmt.Sprintf("%s/%s", remoteDir, exec.FileNameTmp))
    if err != nil {
      //exec.Output <- fmt.Sprintf("host:%s\nFailed to run script: %s\n", host, err.Error())
      exec.Output <- executorResponse(host, fmt.Sprintf("Failed to run script: %s\n", host, err.Error()))
      continue
    }
    //exec.Output <- fmt.Sprintf("host:%s\n%s", host, string(cmdOut))
    exec.Output <- executorResponse(host, string(cmdOut))
  }
}

func executorResponse(host, output string) (ExecutorResponse) {
  return ExecutorResponse{
    Host:   host,
    Output: output,
  }
}
