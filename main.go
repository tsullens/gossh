package main

import (
  "fmt"
)

const VERSION = "0.0.3"
const TERM_CYAN = "\x1b[0;36m"
const TERM_GREEN = "\x1b[0;32m"
const TERM_YELLOW = "\x1b[0;33m"
const TERM_CLEAR = "\033[0m"

var (
 Config *ExecutionConfig
)

func main() {
  Config = newExecutionConfig()

  execute()
}

func execute() {

  var results []ExecutorResponse
  if Config.Verbose {
    fmt.Printf("Running with %d goroutines\n", Config.Routines)
  }
  for i := 0; i < Config.Routines; i++ {
    go Config.Handler.Run()
  }

  go func() {
    for _, host := range Config.ServerList {
      Config.ComChannel.JobChannel <- host
    }
    close(Config.ComChannel.JobChannel)
  }()

  // Really don't know that this is the idiomatic way to do this.
  // Maybe need to think of a better way to handle this whole section of code
  for i := 0; i < len(Config.ServerList); i++ {
    select {
    case result := <- Config.ComChannel.ResponseChannel:
      results = append(results, result)
    }
  }
  //wg.Wait()
  for _, result := range results {
    fmt.Printf("Host: %s%s%s", TERM_GREEN, result.Host, TERM_CLEAR)
    fmt.Printf("%s\n", result.ResponseData)
    fmt.Printf("--------------------------------\n")
  }
}
