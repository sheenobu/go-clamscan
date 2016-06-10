package clamscan

import (
	"bufio"
	"io"
	"os/exec"
	"strings"
)

// Standard scanning of files

// A Result is the information generated from a scan
type Result struct {
	File  string
	Found bool
	Error error
	Virus string
}

// Scan starts a file scan and returns a channel that emits the scanning results
func Scan(opts *Options, files ...string) (<-chan *Result, error) {

	var arguments []string

	setDefaults(opts)

	arguments = append(arguments, "--no-summary")

	for _, i := range opts.ExtraArguments {
		arguments = append(arguments, i)
	}

	for _, file := range files {
		arguments = append(arguments, file)
	}

	cmd := exec.Command(opts.BinaryLocation, arguments...)
	r, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}

	cmd.Start()

	res := make(chan *Result, len(files))

	rx := bufio.NewReader(r)

	go func() {

		defer close(res)

		for {
			line, err := rx.ReadString('\n')
			if err != nil {
				if err == io.EOF {
					return
				}

				res <- &Result{
					File:  "",
					Error: err,
				}

				continue
			}

			i := strings.Split(strings.TrimSpace(line), ":")

			status := strings.TrimSpace(i[1])

			switch status {
			case "OK":
				res <- &Result{
					File:  i[0],
					Found: false,
				}
			case "Empty file":
				res <- &Result{
					File:  i[0],
					Found: false,
				}
			default:
				res <- &Result{
					File:  i[0],
					Found: true,
					Virus: i[1],
				}
			}
		}
	}()

	return res, nil
}
