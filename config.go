package main
import (
  flag "github.com/spf13/pflag"
  "golang.org/x/crypto/ssh/terminal"
  "golang.org/x/crypto/ssh"
  "golang.org/x/crypto/ssh/knownhosts"
  "io/ioutil"
  "runtime"
  "syscall"
  "log"
  "os"
  "strings"
  "fmt"
  "time"
)

type ExecutionConfig struct {
  Handler           Executor
  Routines          int
  ServerList        ServerList
  SSHPort           int
  SSHClientConfig   *ssh.ClientConfig
  Sudo              bool
  Verbose           bool
  ComChannel        *ExecutorCom
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

func (c *ExecutionConfig) logVerbose(msg string) {
  if c.Verbose {
    fmt.Println(msg)
  }
}

func newExecutionConfig() (*ExecutionConfig) {

  var (
    executor             Executor
    servers              ServerList
    goroutines           int
    err                  error
    hostKeyCallback      ssh.HostKeyCallback
    flagHelp             bool
    flagUser             string
    flagIdentityFile     string
    flagSudo             bool
    flagVerbose          bool
    flagScript           string
    flagPort             int
    flagProcs            int
    flagVersion          bool
    flagKnownHostsFile   string
    flagStrictHostCheck  bool
  )

  flag.BoolVarP(&flagHelp, "help", "h", false, "Print Help / Usage")
  flag.StringVarP(&flagUser, "user", "u", os.Getenv("USER"), "Username for SSH connection. Required only if the SSH user differs from the ENV(\"USER\") value or if it is empty.")
  flag.StringVarP(&flagIdentityFile, "IdentityFile", "i", "", "Private Key file for SSH connection. Required only if an SSH Key other than ~/.ssh/id_rsa is to be used. Password fallback is enabled.")
  flag.StringVar(&flagKnownHostsFile, "KnownHostsFile", fmt.Sprintf("%s/.ssh/known_hosts", os.Getenv("HOME")), "Location of known_hosts file.")
  flag.BoolVar(&flagStrictHostCheck, "NoStrictHostCheck", false, "Disable Host Key Checking. Insecure.")
  flag.BoolVarP(&flagSudo, "sudo", "s", false, "Use sudo for command execution. Optional.")
  flag.BoolVarP(&flagVerbose, "verbose", "v", false, "Display verbose output. Optional.")
  flag.StringVarP(&flagScript, "script", "S", "", "Path to script file to run on remote machines. Optional, however this or a list of commands is required.")
  flag.IntVarP(&flagPort, "port", "p", 22, "Port for SSH connection. Optional.")
  flag.IntVar(&flagProcs, "procs", runtime.NumCPU(), "Number of goroutines to use. Optional. This value reflects the number of goroutines concurrently executing SSH Sessions, by default the NumCPUs is used.")
  flag.BoolVarP(&flagVersion, "version", "V", false, "Print version")
  flag.Parse()

  if flagHelp {
    usage(0)
  }
  if flagVersion {
    fmt.Println(VERSION)
    os.Exit(0)
  }
  // Setting our User
  if flagUser == "" {
    usage(1, "Username required.")
  }
  if len(flag.Args()) < 1 {
    usage(2, "At least one argument (host) is required.")
  } else {
    servers, err = NewServerList(flag.Arg(0))
    if err != nil {
      usage(3, fmt.Sprintf("Server list could not be parsed: %s", err.Error()))
    }
  }
  /*
    This sets the number of go routines we will use for parallel execution.
    A -1 provided for this flag will have us create an Executor for every server,
    or if the amount of servers given is lower than our provided or default flagProcs
    value, we will limit ourselves so as to not create unnecessary threads.
  */
  if flagProcs == -1 || len(servers) < flagProcs {
    goroutines = len(servers)
  }

  executorComChannel := &ExecutorCom{
    JobChannel:        make(chan string, 100),
    ResponseChannel:   make(chan ExecutorResponse, 100),
  }

  if flagScript != "" {
    executor, err = NewScriptExecutor(flagScript, executorComChannel)
    if err != nil {
      log.Fatal("Could not create ScriptExecutor: ", err)
    }
  } else if len(flag.Args()[1:]) > 0 {
    executor = NewCommandExecutor(flag.Args()[1:], executorComChannel)
  } else {
    usage(3, "No script or commands provided.")
  }
  // Unless explicity stated via the flag, we should check Host Keys against known_hosts.
  if flagStrictHostCheck {
    hostKeyCallback = ssh.InsecureIgnoreHostKey()
  } else {
    hostKeyCallback, err = knownhosts.New(fmt.Sprintf(flagKnownHostsFile))
    if err != nil {
      log.Fatal("Could not parse known_hosts file: ", err)
    }
  }

  sshClientConfig := &ssh.ClientConfig{
    User:             flagUser,
    HostKeyCallback:  hostKeyCallback,
    Timeout:          time.Duration(int64(time.Second * 20)),
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
      password, err := passwordPrompt()
      if err != nil {
        log.Fatal("Could not read password: ", err)
      }
      sshClientConfig.Auth = []ssh.AuthMethod{
        ssh.PasswordCallback(passwordCallback(password)),
      }
    }
  }

  // Setting our full ExecutionConfig
  return &ExecutionConfig{
    Handler:          executor,
    Routines:         goroutines,
    ServerList:       servers,
    SSHPort:          flagPort,
    SSHClientConfig:  sshClientConfig,
    Sudo:             flagSudo,
    Verbose:          flagVerbose,
    ComChannel:       executorComChannel,
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
