package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
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
	pidsLimit := int64(128)
	resp, err := m.cli.ContainerCreate(
		ctx,
		&container.Config{Image: image, Cmd: []string{"sleep", "infinity"}},
		&container.HostConfig{
			Resources: container.Resources{
				Memory:    256 * 1024 * 1024,
				PidsLimit: &pidsLimit,
			},
			CapDrop:     []string{"ALL"},
			CapAdd:      []string{"SYS_PTRACE"}, // strace needs this to trace the sample
			SecurityOpt: []string{"no-new-privileges"},
			// Executable (not Docker's default noexec) so the sandbox can still
			// observe drop-and-execute malware behavior; see docs/concepts.md.
			// Safe to combine with ReadonlyRootfs only because
			// CopyFileIntoContainer writes through an exec+stdin stream, not
			// the Docker API's CopyToContainer — that call refuses to write
			// into a container at all when ReadonlyRootfs is set, even into a
			// writable tmpfs mount at the destination path.
			ReadonlyRootfs: true,
			Tmpfs:          map[string]string{"/tmp": "exec", "/samples": "exec"},
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

// CopyFileIntoContainer writes localPath's contents into destDir inside the
// container, under the same base filename. It streams the data through a
// non-TTY exec's stdin (`cat > <dest>`) rather than the Docker API's
// CopyToContainer, because CopyToContainer refuses to write into a
// container at all when ReadonlyRootfs is set — even into a writable
// tmpfs mount at the destination — regardless of the mount's own
// permissions; verified directly against the Docker daemon. The exec must
// stay non-TTY (unlike execAndStream's sensor/poller execs, which use
// Tty:true): a PTY's line discipline can interpret control bytes (e.g.
// Ctrl-D/Ctrl-C) that legitimately appear in an arbitrary binary sample,
// corrupting or truncating the transfer.
func (m *DockerManager) CopyFileIntoContainer(ctx context.Context, containerID, localPath, destDir string) error {
	data, err := os.ReadFile(localPath)
	if err != nil {
		return err
	}
	destPath := path.Join(destDir, filepath.Base(localPath))

	execID, err := m.cli.ContainerExecCreate(ctx, containerID, types.ExecConfig{
		Cmd:          []string{"sh", "-c", "cat > " + shellQuote(destPath)},
		AttachStdin:  true,
		AttachStdout: true,
		AttachStderr: true,
	})
	if err != nil {
		return fmt.Errorf("create copy exec: %w", err)
	}
	attach, err := m.cli.ContainerExecAttach(ctx, execID.ID, types.ExecStartCheck{})
	if err != nil {
		return fmt.Errorf("attach copy exec: %w", err)
	}
	defer attach.Close()

	if _, err := io.Copy(attach.Conn, bytes.NewReader(data)); err != nil {
		return fmt.Errorf("write file to container: %w", err)
	}
	if err := attach.CloseWrite(); err != nil {
		return fmt.Errorf("close copy exec stdin: %w", err)
	}

	// Drain stdout/stderr to EOF — content is discarded (this is a
	// multiplexed stream since Tty is false, but we only care that reading
	// to EOF means the exec process has finished) so the ContainerExecInspect
	// below reports the real exit code, not a still-running process's zero
	// value.
	io.Copy(io.Discard, attach.Reader)

	inspect, err := m.cli.ContainerExecInspect(ctx, execID.ID)
	if err != nil {
		return fmt.Errorf("inspect copy exec: %w", err)
	}
	if inspect.ExitCode != 0 {
		return fmt.Errorf("copy into container exited %d", inspect.ExitCode)
	}
	return nil
}

// shellQuote wraps s in single quotes for safe use as one shell word,
// escaping any single quotes it contains. destPath is always built from a
// caller-controlled destDir plus filepath.Base of the uploaded filename
// (path.Join already strips any directory components), but this avoids
// depending on that filename never containing shell metacharacters.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
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

	// ctx's deadline isn't otherwise enforced once the attach connection is
	// established, so a hung or slow-running command would keep streaming
	// past it. Closing the connection here forces the scan loop above to
	// exit and the channel to close.
	go func() {
		<-ctx.Done()
		attach.Close()
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
