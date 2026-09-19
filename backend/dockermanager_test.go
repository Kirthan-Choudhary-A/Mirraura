package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestShadowNetworkAndContainerLifecycle(t *testing.T) {
	dm, err := NewDockerManager()
	if err != nil {
		t.Fatalf("NewDockerManager: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	networkID, err := dm.CreateShadowNetwork(ctx, "mirraura-test-net")
	if err != nil {
		t.Fatalf("CreateShadowNetwork: %v", err)
	}

	containerID, err := dm.StartShadowContainer(ctx, "alpine:3.19", networkID, "mirraura-test-container")
	if err != nil {
		t.Fatalf("StartShadowContainer: %v", err)
	}

	if err := dm.Teardown(ctx, containerID, networkID); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
}

func TestIsolateAndReconnectContainer(t *testing.T) {
	dm, err := NewDockerManager()
	if err != nil {
		t.Fatalf("NewDockerManager: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	networkID, err := dm.CreateShadowNetwork(ctx, "mirraura-isolate-test-net")
	if err != nil {
		t.Fatalf("CreateShadowNetwork: %v", err)
	}
	containerID, err := dm.StartShadowContainer(ctx, "alpine:3.19", networkID, "mirraura-isolate-test-container")
	if err != nil {
		t.Fatalf("StartShadowContainer: %v", err)
	}
	defer dm.Teardown(context.Background(), containerID, networkID)

	if err := dm.IsolateContainer(ctx, "mirraura-isolate-test-net", "mirraura-isolate-test-container"); err != nil {
		t.Fatalf("IsolateContainer: %v", err)
	}
	if err := dm.ReconnectContainer(ctx, "mirraura-isolate-test-net", "mirraura-isolate-test-container"); err != nil {
		t.Fatalf("ReconnectContainer: %v", err)
	}
}

func TestShadowContainerIsHardened(t *testing.T) {
	dm, err := NewDockerManager()
	if err != nil {
		t.Fatalf("NewDockerManager: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	networkID, err := dm.CreateShadowNetwork(ctx, "mirraura-hardening-test-net")
	if err != nil {
		t.Fatalf("CreateShadowNetwork: %v", err)
	}
	containerID, err := dm.StartShadowContainer(ctx, "alpine:3.19", networkID, "mirraura-hardening-test-container")
	if err != nil {
		t.Fatalf("StartShadowContainer: %v", err)
	}
	defer dm.Teardown(context.Background(), containerID, networkID)

	inspect, err := dm.cli.ContainerInspect(ctx, containerID)
	if err != nil {
		t.Fatalf("ContainerInspect: %v", err)
	}
	hc := inspect.HostConfig
	if hc.Memory != 256*1024*1024 {
		t.Errorf("expected 256MB memory limit, got %d", hc.Memory)
	}
	if hc.PidsLimit == nil || *hc.PidsLimit != 128 {
		t.Errorf("expected PidsLimit 128, got %v", hc.PidsLimit)
	}
	if len(hc.CapDrop) != 1 || hc.CapDrop[0] != "ALL" {
		t.Errorf("expected CapDrop [ALL], got %v", hc.CapDrop)
	}
	if len(hc.CapAdd) != 1 || hc.CapAdd[0] != "SYS_PTRACE" {
		t.Errorf("expected CapAdd [SYS_PTRACE] (strace needs it), got %v", hc.CapAdd)
	}
	found := false
	for _, opt := range hc.SecurityOpt {
		if opt == "no-new-privileges" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected no-new-privileges in SecurityOpt, got %v", hc.SecurityOpt)
	}
	if !hc.ReadonlyRootfs {
		t.Error("expected ReadonlyRootfs true")
	}
	if hc.Tmpfs["/tmp"] != "exec" {
		t.Errorf("expected /tmp tmpfs mounted exec, got %q", hc.Tmpfs["/tmp"])
	}
	if hc.Tmpfs["/samples"] != "exec" {
		t.Errorf("expected /samples tmpfs mounted exec, got %q", hc.Tmpfs["/samples"])
	}
}

// TestCopyFileIntoHardenedContainerSucceeds guards against the exact
// regression this project shipped once already: CopyFileIntoContainer must
// actually work against a container hardened with ReadonlyRootfs+Tmpfs
// (StartShadowContainer's real, production config), not just against a
// plain container. Docker's CopyToContainer API refuses to write into any
// container with ReadonlyRootfs set, even into a writable tmpfs mount at
// the destination path — this test exercises the real
// StartShadowContainer -> CopyFileIntoContainer path end to end so a
// regression back to CopyToContainer (or any other change that breaks
// writing under this exact hardening combination) fails loudly here
// instead of only surfacing as a live upload failure.
func TestCopyFileIntoHardenedContainerSucceeds(t *testing.T) {
	dm, err := NewDockerManager()
	if err != nil {
		t.Fatalf("NewDockerManager: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	networkID, err := dm.CreateShadowNetwork(ctx, "mirraura-copy-test-net")
	if err != nil {
		t.Fatalf("CreateShadowNetwork: %v", err)
	}
	containerID, err := dm.StartShadowContainer(ctx, "alpine:3.19", networkID, "mirraura-copy-test-container")
	if err != nil {
		t.Fatalf("StartShadowContainer: %v", err)
	}
	defer dm.Teardown(context.Background(), containerID, networkID)

	localPath := filepath.Join(t.TempDir(), "sample.txt")
	want := "hello from the host"
	if err := os.WriteFile(localPath, []byte(want), 0644); err != nil {
		t.Fatalf("write local temp file: %v", err)
	}

	if err := dm.CopyFileIntoContainer(ctx, containerID, localPath, "/samples/"); err != nil {
		t.Fatalf("CopyFileIntoContainer: %v", err)
	}

	lines, err := dm.execAndStream(ctx, containerID, []string{"cat", "/samples/sample.txt"})
	if err != nil {
		t.Fatalf("execAndStream cat: %v", err)
	}
	var got []string
	for line := range lines {
		got = append(got, line)
	}
	if joined := strings.Join(got, ""); joined != want {
		t.Fatalf("expected copied file content %q, got %q", want, joined)
	}
}

func TestExecAndStreamStopsWhenContextCanceled(t *testing.T) {
	dm, err := NewDockerManager()
	if err != nil {
		t.Fatalf("NewDockerManager: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	networkID, err := dm.CreateShadowNetwork(ctx, "mirraura-timeout-test-net")
	if err != nil {
		t.Fatalf("CreateShadowNetwork: %v", err)
	}
	containerID, err := dm.StartShadowContainer(ctx, "alpine:3.19", networkID, "mirraura-timeout-test-container")
	if err != nil {
		t.Fatalf("StartShadowContainer: %v", err)
	}
	defer dm.Teardown(context.Background(), containerID, networkID)

	execCtx, execCancel := context.WithTimeout(ctx, 2*time.Second)
	defer execCancel()

	lines, err := dm.execAndStream(execCtx, containerID, []string{"sleep", "60"})
	if err != nil {
		t.Fatalf("execAndStream: %v", err)
	}

	start := time.Now()
	for range lines {
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("expected stream to stop shortly after the 2s context deadline, took %v", elapsed)
	}
}
