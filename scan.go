package clamscan

import (
	"os"

	"bufio"
	"io"
	"os/exec"
	"strings"

	"fmt"
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

	res := make(chan *Result, len(files))

	var arguments []string

	if opts == nil {
		opts = &Options{}
	}

	setDefaults(opts)

	arguments = append(arguments, "--no-summary")

	for _, i := range opts.ExtraArguments {
		arguments = append(arguments, i)
	}

	fileCount := 0
	for _, file := range files {
		f, err := os.Open(file)
		if err != nil {
			res <- &Result{
				File:  file,
				Error: err,
			}
			continue
		}
		if _, err = f.Stat(); err != nil {
			f.Close()
			res <- &Result{
				File:  file,
				Error: err,
			}
			continue
		}
		f.Close()
		fileCount++
		arguments = append(arguments, file)
	}

	if fileCount == 0 {
		close(res)
		return res, nil
	}

	opts.DebugLogFunc(fmt.Sprintf("Executing %s %v", opts.BinaryLocation, arguments))

	cmd := exec.Command(opts.BinaryLocation, arguments...)
	r, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	rx := bufio.NewReader(r)

	cmd.Start()
	go func() {
		count := 0
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
			}

			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			count++

			f := func(c rune) bool {
				return c == ':'
			}

			i := strings.FieldsFunc(line, f)

			status := strings.TrimSpace(i[1])

			if len(status) > len("FOUND") {
				if status[len(status)-len("FOUND"):len(status)] == "FOUND" {
					res <- &Result{
						File:  i[0],
						Found: true,
						Virus: strings.TrimSpace(status[0 : len(status)-len("FOUND")]),
					}
					continue
				}
			}

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
			}
		}

		if count == len(files) {
			return
		}
		cmd.Wait()
		err = fmt.Errorf("Unexpected end of clamscan process (%s)",
			cmd.ProcessState.String())

		res <- &Result{
			File:  "",
			Error: err,
		}

	}()

	return res, nil
}
