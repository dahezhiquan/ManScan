//go:build !unix

package service

import (
	"errors"
	"os"
	"os/exec"
)

func prepareTaskCommand(cmd *exec.Cmd) {
	_ = cmd
}

func terminateTaskCommand(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}

	if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	return nil
}

func interruptTaskCommand(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}

	if err := cmd.Process.Signal(os.Interrupt); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	return nil
}
