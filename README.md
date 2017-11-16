# gossh
oh my [gossh](https://www.youtube.com/watch?v=WjNssEVlB6M)

Parallel command / script execution over SSH.
Given a (comma-delimited) list of servers, will execute over them in parallel.
Functionality to allow for IP ranges, subnets, possibly more is planned.

```
At least one argument (host) is required.
  -h, --help                    Print Help / Usage
  -u, --user string             Username for SSH connection. Required only if the SSH user differs from the ENV("USER") value or if it is empty (default "tyler")
  -i, --IdentityFile string     Private Key file for SSH connection. Required only if an SSH Key other than ~/.ssh/id_rsa is to be used. Password fallback is enabled.
  -s, --sudo                    Use sudo for command execution. Optional.
  -v, --verbose                 Display verbose output. Optional.
  -S, --script string           Path to script file to run on remote machines. Optional, however this or a list of commands is required.
  -p, --port int                Port for SSH connection. Optional. (default 22)
      --procs int               Number of goroutines to use. Optional. This value reflects the number of goroutines concurrently executing SSH Sessions, by default the NumCPUs is used. (default 4)
  -V, --version                 Print version
      --KnownHostsFile string   Location of known_hosts file. (default "/Users/tyler/.ssh/known_hosts")
      --NoStrictHostCheck       Disable Host Key Checking. Insecure.
```

Gossh config file (>= v0.3):
```
#toml
[*.sullens.com]
user=tsullens
NoStrictHostCheck=true
sudo=true

[aws-ec2.sullens.com]
user=root
IdentityFile=/home/tyler/.ssh/aws_rsa
```
