//go:build unix

package service

import (
	"context"
	"io"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

func TestTerminateTaskCommandAfterGroupLeaderExits(t *testing.T) {
	// A go-run launcher can exit before its scanner child. The child keeps
	// inherited output pipes open until the entire process group is stopped.
	cmd := exec.Command("sh", "-c", "sleep 30 &")
	prepareTaskCommand(cmd)
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) })
	if _, err := cmd.Process.Wait(); err != nil {
		t.Fatal(err)
	}
	if err := terminateTaskCommand(cmd); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := io.Copy(io.Discard, output)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("scanner descendant still holds stdout after cancellation")
	}
}

func TestTaskCommandContextCancellationStopsProcessGroup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := exec.CommandContext(ctx, "sh", "-c", "sleep 30 & echo ready; wait")
	prepareTaskCommand(cmd)
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) })
	ready := make([]byte, len("ready\n"))
	if _, err := io.ReadFull(output, ready); err != nil {
		t.Fatal(err)
	}
	cancel()
	done := make(chan error, 1)
	go func() {
		_, readErr := io.Copy(io.Discard, output)
		waitErr := cmd.Wait()
		if readErr != nil {
			done <- readErr
			return
		}
		done <- waitErr
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled command unexpectedly succeeded")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("context cancellation left scanner descendant running")
	}
}
