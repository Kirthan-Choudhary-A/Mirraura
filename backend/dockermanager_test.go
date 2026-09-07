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
