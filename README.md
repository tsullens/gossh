# Valor
**(not a great name)**

Parallel command / script execution over SSH.
Given a (comma-delimited) list of servers, will execute over them in parallel.
Functionality to allow for IP ranges, subnets, possibly more is planned.

```
-h, --help             Print Help / Usage
-i, --keyfile string   Private Key file for SSH connection. Required only if an SSH Key other than ~/.ssh/id_rsa is to be used. Password fallback is
                       enabled.
-p, --port int         Port for SSH connection. Optional. (default 22)
    --procs int        Number of goroutines to use. Optional. This value reflects the number of goroutines concurrently executing SSH Sessions, by default
                       the NumCPUs is used. (default 4)
-S, --script string    Path to script file to run on remote machines. Optional, however this or a list of commands is required.
-s, --sudo             Use sudo for command execution. Optional.
-u, --user string      Username for SSH connection. Required only if the SSH user differs from the ENV("USER") value or if it is empty. (default "tyler")
-v, --verbose          Display verbose output. Optional.
-V, --version          Print version
```
