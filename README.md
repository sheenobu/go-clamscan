# go-clamscan

Run and invoke clamscan from go programs.

## Modes

### clamscan.Run

Launches as a long running exec.Command and
input is written to the commands standard input.

### clamscan.Scan

Launches a single clamscan instance to scan a list of files, returning a channel
that emits the results
