package main

import (
  flag "github.com/spf13/pflag"
  "golang.org/x/crypto/ssh/terminal"
  "golang.org/x/crypto/ssh"
  "io/ioutil"
  "strings"
  "fmt"
  "os"
  "log"
  "syscall"
)

type ExecutionContext struct {
  Handler           Executor
  ServerIp          string
  SSHPort           int
  SSHClientConfig   *ssh.ClientConfig
  Sudo              bool
  Verbose           bool
  ComChannel        chan string
}

var (
 flagHelp bool
 flagUser string
 flagIdentityFile string
 flagSudo bool
 flagVerbose bool
 flagScript string
 flagPort int
 //flagEnv string
 ExecContext *ExecutionContext
)

func main() {
  load()
  fmt.Printf("%+v\n", ExecContext)

  worker := &Worker{ServerIp: ExecContext.ServerIp}
  worker.Run()
}

func load() {

  flag.BoolVarP(&flagHelp, "help", "h", false, "Print Help / Usage")
  flag.StringVarP(&flagUser, "user", "u", "", "Username for SSH connection")
  flag.StringVarP(&flagIdentityFile, "keyfile", "i", "", "Private Key file for SSH connection")
  flag.BoolVarP(&flagSudo, "sudo", "s", false, "Use sudo for command execution")
  flag.BoolVarP(&flagVerbose, "verbose", "v", false, "Display verbose output")
  flag.StringVar(&flagScript, "script", "", "Path to script file to run on remote machines")
  flag.IntVarP(&flagPort, "port", "p", 22, "Port for SSH connection")
  flag.Parse()

  if flagHelp {
    usage(0)
  }
  // Setting our User
  if flagUser == "" {
    usage(1, "Username required.")
  }
  if flag.Args() < 1 {
    usage(2, "At least one argument (host) is required.")
  }

  comChannel := make(chan string)

  if flagScript != "" {
    executor, err := NewScriptExecutor(flagScript, comChannel)
    if err != nil {
      log.Fatal("Could not create ScriptExecutor: ", err)
    }
  } else if flag.Args()[1:] > 0 {
    executor := NewCommandExecutor(flag.Args()[1:], comChannel)
  } else {
    usage(3, "No script or commands provided.")
  }

  sshClientConfig := &ssh.ClientConfig{
    User: flagUser,
    HostKeyCallback: ssh.InsecureIgnoreHostKey(), // Temporary, should enforce Host Key Checking
  }
  // Let's work out our Authentication Method
  if flagIdentityFile != "" { // We've been provided a specific keyfile argument
    sshClientConfig.Auth = []ssh.AuthMethod{
      ssh.PublicKeys(getPrivateKey(flagIdentityFile, true)),
    }
  } else { // No specific file was given, let's see if we can find an id_rsa
    signer := getPrivateKey(fmt.Sprintf("%s/.ssh/id_rsa", os.Getenv("HOME")), false)
    if signer != nil {
      sshClientConfig.Auth = []ssh.AuthMethod{
        ssh.PublicKeys(signer),
      }
    } else { // No id_rsa found, not keyfile arg, use password Auth
      sshClientConfig.Auth = []ssh.AuthMethod{
        ssh.PasswordCallback(getPassword()),
      }
    }
  }

  // Setting our full ExecutionContext
  ExecContext = &ExecutionContext{
    Handler:          executor,
    ServerIp:         flag.Arg(0),
    SSHPort:          flagPort,
    SSHClientConfig:  sshClientConfig,
    Sudo:             flagSudo,
    Verbose:          flagVerbose,
    ComChannel:       comChannel,
  }

}

func usage(exitstatus int, msg ...string) {
  if len(msg) > 0 {
    fmt.Println(msg[0]) // We should only ever provide 1 extra arg to this function
  }
  // https://godoc.org/github.com/spf13/pflag#pkg-variables
  flag.PrintDefaults()
  os.Exit(exitstatus)
}

// Callback Method: returns a func to be used in a Callback.
func getPassword() (func() (string, error)) {
  return func() (string, error) {
    fmt.Print("Password: ")
    password, err := terminal.ReadPassword(int(syscall.Stdin))
    if err != nil {
      return "", err
    }
    return strings.TrimSpace(string(password)), nil
  }
}

// This is kinda a hacky method right now. There's two cases we want to use this:
// 1. To check if an id_rsa exists & is usable: we don't want to Fatal
// 2. If a specific keyfile is passed as an arg we want to Fatal if we can't use it.
func getPrivateKey(identityFile string, failOnErr bool) (ssh.Signer) {
  key, err := ioutil.ReadFile(identityFile)
  if err != nil {
    if failOnErr {
      log.Fatal("Could not read Identity File: ", err)
    }
    return nil
  }
  signer, err := ssh.ParsePrivateKey(key)
  if err != nil {
    log.Fatal("Could not parse private key: ", err)
  }
  return signer
}

func getScriptSrc(scriptPath string) ([]byte) {
  if scriptPath == "" {
    return nil
  }
  scriptSrc, err := ioutil.ReadFile(scriptPath)
  if err != nil {
    log.Fatal("Could not read script: ", err)
  }
  return scriptSrc
}

func (ec *ExecutionContext) Print() {
  // Print the Exection Context in a readable format
  //fmt.Printf("ExectionContext:\n")
  //fmt.Printf("ServerIp: %s\n", ec.ServerIp)
  //fmt.Printf("SSHPort: %d\n", ec.SSHPort)
  //fmt.Printf("Commands: %s\n", strings.Join(ec.Commands, ", "))
  //fmt.Printf("")
}

/*
  Probably want to try to implement the ability to enforce Host Key Checking
  by default at some point. For now, I think I'll just have to be Insecure.

// Type HostKeyCallback
// https://godoc.org/golang.org/x/crypto/ssh#HostKeyCallback
func LookupHostKey() HostKeyCallBack {
  return func(hostname string, remote net.Addr, key PublicKey) error {

  }
}
*/
