package clamscan

import (
	"bufio"
	"io"
	"os/exec"
	"strings"
	"sync"
)

// A Service is a long running clamscan process that you send files to
type Service struct {
	closeChan chan struct{} //TODO:replace with context.Context?
	closeOnce sync.Once

	cmd *exec.Cmd
	r   *bufio.Reader
	w   io.WriteCloser

	opts *Options
}

// Run runs the clamscan service and returns it
func Run(opts *Options) (*Service, error) {

	if opts == nil {
		opts = &Options{}
	}

	setDefaults(opts)

	var arguments []string

	arguments = append(arguments, "--file-list")
	arguments = append(arguments, opts.StdinPath)
	arguments = append(arguments, "--no-summary")

	for _, i := range opts.ExtraArguments {
		arguments = append(arguments, i)
	}

	cmd := exec.Command(opts.BinaryLocation, arguments...)

	r, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}

	w, err := cmd.StdinPipe()
	if err != nil {
		r.Close()
		return nil, err
	}

	closeChan := make(chan struct{})
	if err := cmd.Start(); err != nil {
		w.Close()
		r.Close()
		return nil, err
	}

	go func() {
		<-closeChan
		r.Close()
		w.Close()
	}()

	return &Service{
		closeChan: make(chan struct{}),
		cmd:       cmd,
		r:         bufio.NewReader(r),
		w:         w,
		opts:      opts,
	}, nil

}

// Scan scans the file and returns the result
func (s *Service) Scan(file string) *Result {
	//TODO: stat file before sending to clamscan

	if _, err := s.w.Write([]byte(file + "\n")); err != nil {
		return &Result{
			Error: err,
		}
	}

	line, err := s.r.ReadString('\n')
	if err != nil {
		return &Result{
			Error: err,
		}
	}

	i := strings.Split(strings.TrimSpace(line), ":")

	status := strings.TrimSpace(i[1])

	switch status {
	case "OK":
		return &Result{
			File:  i[0],
			Found: false,
		}
	case "Empty file":
		return &Result{
			File:  i[0],
			Found: false,
		}
	default:
		return &Result{
			File:  i[0],
			Found: true,
			Virus: i[1],
		}
	}
}

// Close closes the service and stops clamscan
func (s *Service) Close() {
	s.closeOnce.Do(func() {
		close(s.closeChan)
	})
}
