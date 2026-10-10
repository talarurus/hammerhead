package reporter

import "io"

// OutputWriter latches the first output failure, including a nil-error short
// write. Later writes never reach the destination. It is local to one invocation.
type OutputWriter struct {
	destination io.Writer
	err         error
	flushed     bool
}

func NewOutputWriter(w io.Writer) *OutputWriter {
	return &OutputWriter{destination: w}
}

func (w *OutputWriter) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	w.flushed = false
	if w.destination == nil {
		w.err = io.ErrClosedPipe
		return 0, w.err
	}
	n, err := w.destination.Write(p)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	w.err = err
	return n, err
}

func (w *OutputWriter) Err() error { return w.err }

// Flush also checks caller-supplied buffering. No buffering is introduced here.
// Repeated finalization is harmless when reporters share the CLI's writer.
func (w *OutputWriter) Flush() error {
	if w.err == nil && !w.flushed {
		w.flushed = true
		if f, ok := w.destination.(interface{ Flush() error }); ok {
			w.err = f.Flush()
		}
	}
	return w.err
}
