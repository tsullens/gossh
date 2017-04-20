package main

import (
  "golang.org/x/crypto/ssh"
  "golang.org/x/crypto/sha3"
  "github.com/tmc/scp"
  "fmt"
  "log"
  "io"
  "os"
)

type Executor interface {
  Run()
}

type CommandExecutor struct {
  Commands    []string
  ComChannel  *ExecutorCom
}

type ScriptExecutor struct {
  FileSize      int64
  FileReader    io.Reader
  FileNameTmp   string
  ComChannel    *ExecutorCom
}

type ExecutorCom struct {
  Input   chan string
  Output  chan ExecutorResponse
}

type ExecutorResponse struct {
  Id      Int
  Host    string
  Output  string
}

func NewCommandExecutor(cmds []string, com *ExecutorCom) (*CommandExecutor) {
  return &CommandExecutor{
    Commands:     cmds,
    ComChannel:   com,
  }
}

func NewScriptExecutor(file string, com *ExecutorCom) (*ScriptExecutor, error) {
  f, err := os.Open(file)
  if err != nil {
    return err
  }
  defer f.Close()
  s, err := f.Stat()
  if err != nil {
    return err
  }
  h := make([]byte, 64)
  ShakeSum256(h, []byte(file))

  h.Write([]byte(file))
  return &ScriptExecutor{
    FileSize:     s.Size(),
    FileReader:   f,
    FileNameTmp:  string(h),
    ComChannel:   com,
  }
}

func (exec *CommandExecutor) Run() {

  for host := range exec.ExecutorCom.Input {
    client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", host, ExecContext.SSHPort), ExecContext.SSHClientConfig)
    if err != nil {
      exec.Output <- &ExecutorResponse{
        Id:
      }
    }

    for _, cmd := range ExecContext.Commands {
      session, err := client.NewSession()
      if err != nil {
        exec.Output <- fmt.Sprintf("host:%s\nFailed to create session: %s\n", host, err.Error())
      }
      defer session.Close()
      cmdOut, err := session.CombinedOutput(cmd)
      if err != nil {
          exec.Output <- fmt.Sprintf("host:%s\nFailed to run cmd (%s): %s", host, cmd, err.Error())
      }
      exec.Output <- fmt.Sprintf("host:%s\n%s", cmdOut)
    }
  }
}

func (exec *ScriptExecutor) Run() {
  remoteDir := "/tmp"
  err := scp.Copy(exec.FileSize, os.FileMode(0755), exec.FileNameTmp, exec.FileReader, remoteDir, ExecContext.SSHClientConfig)
  if err != nil {
    exec.Output <- fmt.Sprintf("host:%s\nFailed to copy script: %s\n", host, err.Error())
    return
  }
  client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", host, ExecContext.SSHPort), ExecContext.SSHClientConfig)
  if err != nil {
    exec.Output <- fmt.Sprintf("host:%s\nFailed to connect & run script: %s\n", host, err.Error())
    return
  }
  session, err := client.NewSession()
  if err != nil {
    exec.Output <- fmt.Sprintf("host:%s\nFailed to create session: %s\n", host, err.Error())
    return
  }
  defer session.Close()
  cmdOut, err := session.CombinedOutput(fmt.Sprintf("%s/%s", remoteDir, exec.FileNameTmp))
  if err != nil {
    exec.Output <- fmt.Sprintf("host:%s\nFailed to run script: %s\n", host, err.Error())
    return
  }
  session.Close()
  session, err := client.NewSession()
  if err != nil {
    exec.Output <- fmt.Sprintf("host:%s\nFailed to create session: %s\n", host, err.Error())
    return
  }
  defer session.Close()
  cmdOut, err := session.CombinedOutput(fmt.Sprintf("rm -rf %s/%s", remoteDir, exec.FileNameTmp))
  if err != nil {
    exec.Output <- fmt.Sprintf("host:%s\nFailed to delete script: %s\n", host, err.Error())
    return
  }
  exec.Output <- fmt.Sprintf("host:%s\n%s", host, string(cmdOut))
  return
}
