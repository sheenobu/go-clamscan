package clamscan

import (
	"testing"
)

func TestScan(t *testing.T) {

	o := &Options{
		ExtraArguments: []string{
			"-d", "customsig.ndb",
		},
	}

	t.Run("no-files", func(t *testing.T) {
		res, err := Scan(o)
		if err != nil {
			t.Errorf("Unexpected error: %s\n", err)
		}
		select {
		case _, more := <-res:
			if more {
				t.Errorf("Unexpected more elements")
			}
		}
	})
	t.Run("non-existent-file", func(t *testing.T) {
		res, err := Scan(o, "file1")
		if err != nil {
			t.Errorf("Unexpected error: %s\n", err)
		}
		select {
		case st, more := <-res:
			if !more {
				t.Errorf("Expected more elements")
				return
			}
			if st.Error == nil {
				t.Errorf("Expected error")
				return
			}
			if st.File != "file1" {
				t.Errorf("Expected file to be file1, got %s", st.File)
			}
			if st.Error.Error() != "open file1: no such file or directory" {
				t.Errorf("Expected error as File not found, got %s",
					st.Error.Error())
			}
		}
	})
	t.Run("non-existent-WARNING-file", func(t *testing.T) {
		res, err := Scan(o, "WARNING")
		if err != nil {
			t.Errorf("Unexpected error: %s\n", err)
		}
		select {
		case st, more := <-res:
			if !more {
				t.Errorf("Expected more elements")
				return
			}
			if st.Error == nil {
				t.Errorf("Expected error")
				return
			}
			if st.File != "WARNING" {
				t.Errorf("Expected file to be WARNING, got %s", st.File)
			}
			if st.Error.Error() != "open WARNING: no such file or directory" {
				t.Errorf("Expected error as File not found, got %s",
					st.Error.Error())
			}
		}
	})
	t.Run("empty-file", func(t *testing.T) {
		res, err := Scan(o, "testfile3")
		if err != nil {
			t.Errorf("Unexpected error: %s\n", err)
		}
		select {
		case st, more := <-res:
			if !more {
				t.Errorf("Expected more elements")
				return
			}
			if st.File != "testfile3" {
				t.Errorf("Expected file to be WARNING, got %s", st.File)
			}
			if st.Error != nil {
				t.Errorf("Unexpected error %s",
					st.Error.Error())
			}
			if st.Found {
				t.Errorf("Unexpected virus detection")
			}
		}
	})
	t.Run("good-file", func(t *testing.T) {
		res, err := Scan(o, "testfile2")
		if err != nil {
			t.Errorf("Unexpected error: %s\n", err)
		}
		select {
		case st, more := <-res:
			if !more {
				t.Errorf("Expected more elements")
				return
			}
			if st.File != "testfile2" {
				t.Errorf("Expected file to be WARNING, got %s", st.File)
			}
			if st.Error != nil {
				t.Errorf("Unexpected error %s",
					st.Error.Error())
			}
			if st.Found {
				t.Errorf("Unexpected virus detection")
			}
		}
	})
	t.Run("virus-file", func(t *testing.T) {
		res, err := Scan(o, "testfile")
		if err != nil {
			t.Errorf("Unexpected error: %s\n", err)
		}
		select {
		case st, more := <-res:
			if !more {
				t.Errorf("Expected more elements")
				return
			}
			if st.File != "testfile" {
				t.Errorf("Expected file to be WARNING, got %s", st.File)
			}
			if st.Error != nil {
				t.Errorf("Unexpected error %s",
					st.Error.Error())
			}
			if !st.Found {
				t.Errorf("Expected virus detection")
			}
			if st.Virus != "Trojan.Win32.Emold.A.UNOFFICIAL" {
				t.Errorf("Expected virus '%s', got '%s'", "Trojan.Win32.Emold.A.UNOFFICIAL", st.Virus)
			}
		}
	})
}
