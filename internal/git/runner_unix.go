//go:build unix

package git

import (
	"errors"
	"os/exec"
	"syscall"
)

func setupSysProcAttr(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
}

func terminateProcessGroup(cmd *exec.Cmd) {
	if !ownsProcessGroup(cmd) {
		return
	}
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
}

func forceKillProcessGroup(cmd *exec.Cmd) {
	if !ownsProcessGroup(cmd) {
		return
	}
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}

func processGroupExists(cmd *exec.Cmd) bool {
	if !ownsProcessGroup(cmd) {
		return false
	}
	err := syscall.Kill(-cmd.Process.Pid, 0)
	// Only ESRCH proves absence; permission or other errors must not make
	// cleanup report success.
	return !errors.Is(err, syscall.ESRCH)
}

func ownsProcessGroup(cmd *exec.Cmd) bool {
	return cmd.Process != nil && cmd.Process.Pid > 0 &&
		cmd.SysProcAttr != nil && cmd.SysProcAttr.Setpgid && cmd.SysProcAttr.Pgid == 0 &&
		cmd.Process.Pid != syscall.Getpgrp()
}
