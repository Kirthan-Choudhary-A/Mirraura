package main

import (
	"context"
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
	if _, ok := hc.Tmpfs["/tmp"]; !ok {
		t.Errorf("expected a /tmp tmpfs mount, got %v", hc.Tmpfs)
	}
	if _, ok := hc.Tmpfs["/samples"]; !ok {
		t.Errorf("expected a /samples tmpfs mount, got %v", hc.Tmpfs)
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
