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
