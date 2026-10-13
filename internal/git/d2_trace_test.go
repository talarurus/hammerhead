package git

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestD2Trace_RedactionAndErrorCategories(t *testing.T) {
	const secret = "UNTRUSTED_SENTINEL_VALUE_DO_NOT_EXPORT"
	t.Setenv("HAMMERHEAD_D2_PHASE", secret)
	ctx := d2TestContext(context.Background(), "normal")
	for _, err := range []error{
		&os.PathError{Op: secret, Path: secret, Err: syscall.EACCES},
		&os.SyscallError{Syscall: secret, Err: syscall.EMFILE},
		errors.New(secret), refuse(secret), &GitExitError{ExitCode: 128, Kind: errors.New(secret)},
	} {
		e := d2BuildEvent(ctx, "config-no-includes", time.Now(), err)
		b, marshalErr := json.Marshal(e)
		if marshalErr != nil || strings.Contains(string(b), secret) {
			t.Fatal("trace redaction failed")
		}
	}
	if got := d2Category(&os.PathError{Path: secret, Err: syscall.EACCES}); got != "os-errno" {
		t.Fatal(got)
	}
	if got := d2StderrCategory([]byte("fatal: " + secret)); got != "fatal-other" {
		t.Fatal(got)
	}
	if got := d2Category(context.DeadlineExceeded); got != "deadline" {
		t.Fatal(got)
	}
}
