package main
import (
  "gossh/gossh"
  "github.com/spf13/viper"
  flag "github.com/spf13/pflag"
  "golang.org/x/crypto/ssh"
  "golang.org/x/crypto/ssh/knownhosts"
  "runtime"
  "log"
  "os"
  "fmt"
  "time"
)

const VERSION = "0.4.1"

func main() {
  var (
    servers              gossh.ServerList
    err                  error
    hostKeyCallback      ssh.HostKeyCallback
    proxyHostFlag        string
    helpFlag             bool
    userFlag             string
    passwordFlag         bool
    identityFileFlag     string
    sudoFlag             bool
    //verboseFlag          bool
    scriptFlag           string
    portFlag             int
    procsFlag            int
    versionFlag          bool
    knownHostsFileFlag   string
    strictHostCheckFlag  bool
    sshAgentForwardFlag  bool
  )

  viper := viper.New()
  /*
    Trying to load our gossh config file

  viper.SetConfigName("config")
  viper.AddConfigPath("$HOME/.gossh/")
  viper.SetConfigType("toml")
  err = viper.ReadInConfig()
  if err != nil {
    fmt.Println(err)
  }
  */
  flagSet := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
  flagSet.BoolVarP(&helpFlag, "help", "h", false, "Print Help / Usage")
  flagSet.StringVarP(&userFlag, "user", "l", os.Getenv("USER"), "Username for SSH connection. Required only if the SSH user differs from the ENV(\"USER\") value or if it is empty.")
  flagSet.BoolVarP(&passwordFlag, "pass", "P", false, "Use password authentication for the SSH connection.")
  flagSet.StringVarP(&identityFileFlag, "IdentityFile", "i", fmt.Sprintf("%s/.ssh/id_rsa", os.Getenv("HOME")), "Private Key file for SSH connection. Required only if an SSH Key other than ~/.ssh/id_rsa is to be used. Password fallback is enabled.")
  flagSet.BoolVarP(&sudoFlag, "sudo", "s", false, "Use sudo for command execution. Optional.")
  //flagSet.BoolVarP(&verboseFlag, "verbose", "v", false, "Display verbose output. Optional.")
  flagSet.StringVarP(&scriptFlag, "script", "S", "", "Path to script file to run on remote machines. Optional, however this or a list of commands is required.")
  flagSet.IntVarP(&portFlag, "port", "p", 22, "Port for SSH connection. Optional.")
  flagSet.StringVarP(&proxyHostFlag, "proxy", "J", "", "Bastion / Jumphost to proxy through, in the form of host:port. If no port is supplied, 22 is assumed.")
  flagSet.IntVar(&procsFlag, "procs", runtime.NumCPU(), "Number of goroutines to use. Optional. This value is the number of concurrently executing SSH Sessions, by default the NumCPUs is used.")
  flagSet.BoolVarP(&versionFlag, "version", "v", false, "Print version")
  flagSet.BoolVarP(&sshAgentForwardFlag, "forward", "A", false, "Forward SSH Key from local ssh-agent.")
  flagSet.StringVar(&knownHostsFileFlag, "KnownHostsFile", fmt.Sprintf("%s/.ssh/known_hosts", os.Getenv("HOME")), "Location of known_hosts file.")
  flagSet.BoolVar(&strictHostCheckFlag, "NoStrictHostCheck", false, "Disable Host Key Checking. Insecure.")
  //flagSet.MarkHidden("A")
  flagSet.SortFlags = false
  flagSet.Parse(os.Args[1:])
  viper.BindPFlags(flag.CommandLine)

  if helpFlag {
    usage(flagSet, 0)
  }
  if versionFlag {
    fmt.Println(VERSION)
    os.Exit(0)
  }

  if len(flagSet.Args()) < 1 {
    usage(flagSet, 2, "At least one argument (host) is required.")
  } else {
    servers, err = gossh.NewServerList(flagSet.Arg(0))
    if err != nil {
      usage(flagSet, 3, fmt.Sprintf("Server list could not be parsed: %s", err.Error()))
    }
  }
  gclient := gossh.NewGosshClient(servers).Port(portFlag)
  if proxyHostFlag != "" {
    gclient.ProxyHost(proxyHostFlag)
  }
  if sudoFlag {
    gclient.Sudo()
  }

  /*
    This sets the number of go routines we will use for parallel execution.
    A -1 provided for this flag will have us create an Executor for every server,
    or if the amount of servers given is lower than our provided or default procsFlag
    value, we will limit ourselves so as to not create unnecessary threads.
  */
  if procsFlag == -1 || len(servers) < procsFlag {
    gclient.Routines(len(servers))
  } else {
    gclient.Routines(procsFlag)
  }

  // Unless explicity stated via the flag, we should check Host Keys against known_hosts.
  if strictHostCheckFlag {
    hostKeyCallback = ssh.InsecureIgnoreHostKey()
  } else {
    hostKeyCallback, err = knownhosts.New(fmt.Sprintf(knownHostsFileFlag))
    if err != nil {
      log.Fatal("Could not parse known_hosts file: ", err)
    }
  }

  sshAuthMethods := []ssh.AuthMethod{gossh.PublicKeyAuth(identityFileFlag)}
  if sshAgentForwardFlag {
    sshAuthMethods = append(sshAuthMethods, gossh.AgentAuth())
  }
  if passwordFlag {
    sshAuthMethods = append(sshAuthMethods, gossh.PasswordAuth())
  }

  sshClientConfig := ssh.ClientConfig{
    User:             userFlag,
    Auth:             sshAuthMethods,
    HostKeyCallback:  hostKeyCallback,
    Timeout:          time.Duration(int64(time.Second * 20)),
  }
  gclient.ClientConfig(sshClientConfig)

  var results []*gossh.ClientResponse
  if scriptFlag != "" {
    results, err = gclient.ExecuteScript(scriptFlag)
  } else if len(flagSet.Args()[1:]) > 0 {
    results, err = gclient.ExecuteCommands(flagSet.Args()[1:])
  } else {
    usage(flagSet, 3, "No script or commands provided.")
  }
  if err != nil {
    log.Fatal("Error: ", err)
  } else {
    for _, res := range results {
      fmt.Println(res.String())
    }
  }
}

func usage(flagSet *flag.FlagSet, exitstatus int, msg ...string) {
  if len(msg) > 0 {
    fmt.Println(msg[0]) // We should only ever provide 1 extra arg to this function
  }
  // https://godoc.org/github.com/spf13/pflag#pkg-variables
  fmt.Println("gossh [flags...] server[,server] \"command\"")
  fmt.Println()
  flagSet.PrintDefaults()
  os.Exit(exitstatus)
}
