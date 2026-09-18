package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
)

type DockerManager struct {
	cli *client.Client
}

func NewDockerManager() (*DockerManager, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, err
	}
	return &DockerManager{cli: cli}, nil
}

func (m *DockerManager) CreateShadowNetwork(ctx context.Context, name string) (string, error) {
	resp, err := m.cli.NetworkCreate(ctx, name, types.NetworkCreate{Driver: "bridge", Internal: true})
	if err != nil {
		return "", err
	}
	return resp.ID, nil
}

func (m *DockerManager) StartShadowContainer(ctx context.Context, image, networkID, name string) (string, error) {
	one := int64(128)
	resp, err := m.cli.ContainerCreate(
		ctx,
		&container.Config{Image: image, Cmd: []string{"sleep", "infinity"}},
		&container.HostConfig{
			Resources: container.Resources{
				Memory:     256 * 1024 * 1024,
				PidsLimit:  &one,
			},
			CapDrop:        []string{"ALL"},
			CapAdd:         []string{"SYS_PTRACE"}, // strace needs this to trace the sample
			SecurityOpt:    []string{"no-new-privileges"},
			ReadonlyRootfs: true,
			Tmpfs:          map[string]string{"/tmp": ""},
		},
		&network.NetworkingConfig{
			EndpointsConfig: map[string]*network.EndpointSettings{
				networkID: {},
			},
		},
		nil,
		name,
	)
	if err != nil {
		return "", err
	}
	if err := m.cli.ContainerStart(ctx, resp.ID, types.ContainerStartOptions{}); err != nil {
		return "", err
	}
	return resp.ID, nil
}

func (m *DockerManager) CopyFileIntoContainer(ctx context.Context, containerID, localPath, destDir string) error {
	data, err := os.ReadFile(localPath)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	hdr := &tar.Header{Name: filepath.Base(localPath), Mode: 0755, Size: int64(len(data))}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	if _, err := tw.Write(data); err != nil {
		return err
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return m.cli.CopyToContainer(ctx, containerID, destDir, &buf, types.CopyToContainerOptions{})
}

func (m *DockerManager) execAndStream(ctx context.Context, containerID string, cmd []string) (<-chan string, error) {
	execID, err := m.cli.ContainerExecCreate(ctx, containerID, types.ExecConfig{
		Cmd:          cmd,
		AttachStdout: true,
		AttachStderr: true,
		Tty:          true,
	})
	if err != nil {
		return nil, err
	}
	attach, err := m.cli.ContainerExecAttach(ctx, execID.ID, types.ExecStartCheck{Tty: true})
	if err != nil {
		return nil, err
	}

	lines := make(chan string)
	go func() {
		defer close(lines)
		defer attach.Close()
		scanner := bufio.NewScanner(attach.Reader)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				lines <- line
			}
		}
	}()
	return lines, nil
}

func (m *DockerManager) RunSensor(ctx context.Context, containerID, samplePathInContainer string) (<-chan string, error) {
	return m.execAndStream(ctx, containerID, []string{"/sensor/sensor", samplePathInContainer})
}

func (m *DockerManager) RunPoller(ctx context.Context, containerID string) (<-chan string, error) {
	return m.execAndStream(ctx, containerID, []string{"python3", "/poller/poller.py"})
}

func (m *DockerManager) IsolateContainer(ctx context.Context, networkName, containerName string) error {
	return m.cli.NetworkDisconnect(ctx, networkName, containerName, false)
}

func (m *DockerManager) ReconnectContainer(ctx context.Context, networkName, containerName string) error {
	return m.cli.NetworkConnect(ctx, networkName, containerName, nil)
}

// IsContainerIsolated reports whether containerName is currently NOT attached
// to networkName, i.e. Docker's ground truth for isolation state. Used at
// startup to recover the in-memory isolated flag after a backend restart.
func (m *DockerManager) IsContainerIsolated(ctx context.Context, networkName, containerName string) (bool, error) {
	inspect, err := m.cli.ContainerInspect(ctx, containerName)
	if err != nil {
		return false, err
	}
	_, attached := inspect.NetworkSettings.Networks[networkName]
	return !attached, nil
}

func (m *DockerManager) Teardown(ctx context.Context, containerID, networkID string) error {
	timeout := 5
	_ = m.cli.ContainerStop(ctx, containerID, container.StopOptions{Timeout: &timeout})
	removeErr := m.cli.ContainerRemove(ctx, containerID, types.ContainerRemoveOptions{Force: true})
	networkErr := m.cli.NetworkRemove(ctx, networkID)
	return errors.Join(removeErr, networkErr)
}
