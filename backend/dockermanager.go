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
	resp, err := m.cli.ContainerCreate(
		ctx,
		&container.Config{Image: image, Cmd: []string{"sleep", "infinity"}},
		nil,
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

func (m *DockerManager) RunSensor(ctx context.Context, containerID, samplePathInContainer string) (<-chan string, error) {
	execID, err := m.cli.ContainerExecCreate(ctx, containerID, types.ExecConfig{
		Cmd:          []string{"python3", "/sensor/sensor.py", samplePathInContainer},
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

func (m *DockerManager) Teardown(ctx context.Context, containerID, networkID string) error {
	timeout := 5
	_ = m.cli.ContainerStop(ctx, containerID, container.StopOptions{Timeout: &timeout})
	removeErr := m.cli.ContainerRemove(ctx, containerID, types.ContainerRemoveOptions{Force: true})
	networkErr := m.cli.NetworkRemove(ctx, networkID)
	return errors.Join(removeErr, networkErr)
}
