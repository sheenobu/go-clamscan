package clamscan

// Options are the configurable options for clamscan
type Options struct {
	BinaryLocation string
	ExtraArguments []string
	StdinPath      string
	DebugLogFunc   func(msg string)
}

// setDefaults sets the default values for Options
func setDefaults(opts *Options) {
	if opts.BinaryLocation == "" {
		opts.BinaryLocation = "clamscan"
	}

	if opts.StdinPath == "" {
		opts.StdinPath = "/dev/stdin"
	}
	if opts.DebugLogFunc == nil {
		opts.DebugLogFunc = func(msg string) {

		}
	}
}
