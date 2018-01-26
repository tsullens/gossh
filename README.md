# gossh

Parallel command / script execution over SSH.
Given a (comma-delimited) list of servers, will execute over them in parallel.

Download http://atlas.tcsullens.com/files/gossh/

## v4.1 RC1 release
v4.1 brings many updates:
- Code has been completely refactored, the code implementing the core functionality
  has been implemented as a package and is available for import gossh/gossh.
- Code is hopefully more simplified.
- Using a proxy / jumphost is now an option.
- Existing (known) bugs have been fixed

```
gossh [flags...] server[,server] "command"

  -h, --help                    Print Help / Usage
  -l, --user string             Username for SSH connection. Required only if the SSH user differs from the ENV("USER") value or if it is empty. (default "tyler")
  -P, --pass                    Use password authentication for the SSH connection.
  -i, --IdentityFile string     Private Key file for SSH connection. Required only if an SSH Key other than ~/.ssh/id_rsa is to be used. Password fallback is enabled. (default "/Users/tyler/.ssh/id_rsa")
  -s, --sudo                    Use sudo for command execution. Optional.
  -S, --script string           Path to script file to run on remote machines. Optional, however this or a list of commands is required.
  -p, --port int                Port for SSH connection. Optional. (default 22)
  -J, --proxy string            Bastion / Jumphost to proxy through, in the form of host:port. If no port is supplied, 22 is assumed.
      --procs int               Number of goroutines to use. Optional. This value is the number of concurrently executing SSH Sessions, by default the NumCPUs is used. (default 4)
  -v, --version                 Print version
  -A, --forward                 Forward SSH Key from local ssh-agent.
      --KnownHostsFile string   Location of known_hosts file. (default "/Users/tyler/.ssh/known_hosts")
      --NoStrictHostCheck       Disable Host Key Checking. Insecure.
```
