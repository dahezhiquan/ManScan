//go:build unix

package service

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

func prepareTaskCommand(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
	cmd.SysProcAttr.Pgid = 0
	if cmd.Cancel != nil {
		// CommandContext must terminate the scanner descendants as well as
		// the go-run launcher, otherwise inherited output pipes stay open.
		cmd.Cancel = func() error { return terminateTaskCommand(cmd) }
	}
}

func terminateTaskCommand(cmd *exec.Cmd) error {
	return signalTaskCommand(cmd, syscall.SIGKILL)
}

func interruptTaskCommand(cmd *exec.Cmd) error {
	return signalTaskCommand(cmd, syscall.SIGINT)
}

func signalTaskCommand(cmd *exec.Cmd, signal syscall.Signal) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}

	var err error
	if cmd.SysProcAttr != nil && cmd.SysProcAttr.Setpgid && cmd.SysProcAttr.Pgid == 0 {
		// prepareTaskCommand makes PID the group ID. Do not look it up from
		// the leader: it may already have exited while descendants still run.
		err = syscall.Kill(-cmd.Process.Pid, signal)
	} else {
		err = cmd.Process.Signal(signal)
	}
	if err != nil && !errors.Is(err, syscall.ESRCH) && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	return nil
}
