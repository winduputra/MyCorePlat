package installer

import (
	"archive/tar"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// dockerClient is a minimal Docker Engine API client over the unix socket.
//
// A hand-rolled client keeps the installer free of heavyweight SDK
// dependencies and makes exactly which endpoints are used explicit and
// auditable. Only the operations the installer needs are implemented.
type dockerClient struct {
	http *http.Client
	host string // e.g. unix:///var/run/docker.sock or tcp://host:port
}

// newDockerClient connects to the Docker daemon indicated by DOCKER_HOST,
// defaulting to the local unix socket.
func newDockerClient() (*dockerClient, error) {
	host := os.Getenv("DOCKER_HOST")
	if host == "" {
		host = "unix:///var/run/docker.sock"
	}
	transport := &http.Transport{}
	if strings.HasPrefix(host, "unix://") {
		socketPath := strings.TrimPrefix(host, "unix://")
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socketPath)
		}
	} else {
		return nil, fmt.Errorf("unsupported DOCKER_HOST %q", host)
	}
	return &dockerClient{
		http: &http.Client{Transport: transport, Timeout: 0}, // long builds need no timeout
		host: host,
	}, nil
}

func (c *dockerClient) do(ctx context.Context, method, path string, body io.Reader, contentType string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, "http://docker"+path, body)
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	return c.http.Do(req)
}

// ping verifies the daemon is reachable.
func (c *dockerClient) ping(ctx context.Context) error {
	resp, err := c.do(ctx, http.MethodGet, "/_ping", nil, "")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("docker ping status %d", resp.StatusCode)
	}
	return nil
}

// buildImage streams a tar build context and builds a tagged image. It returns
// the final stream error reported by the daemon, if any.
func (c *dockerClient) buildImage(ctx context.Context, tag, contextDir, dockerfilePath string) error {
	contextTar, err := tarContext(contextDir)
	if err != nil {
		return err
	}
	query := url.Values{}
	query.Set("t", tag)
	query.Set("dockerfile", dockerfilePath)
	query.Set("rm", "1")
	query.Set("forcerm", "1")
	path := "/v1.43/build?" + query.Encode()

	resp, err := c.do(ctx, http.MethodPost, path, contextTar, "application/x-tar")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("build status %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return decodeBuildStream(resp.Body)
}

// buildMessage is the JSON envelope emitted by the Docker build endpoint.
type buildMessage struct {
	Stream string `json:"stream"`
	Error  string `json:"error"`
}

func decodeBuildStream(r io.Reader) error {
	dec := json.NewDecoder(r)
	for {
		var msg buildMessage
		if err := dec.Decode(&msg); err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		if msg.Error != "" {
			return fmt.Errorf("%s", strings.TrimSpace(msg.Error))
		}
	}
}

func (c *dockerClient) removeImage(ctx context.Context, tag string) error {
	resp, err := c.do(ctx, http.MethodDelete, "/v1.43/images/"+url.PathEscape(tag)+"?force=1", nil, "")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("remove image status %d", resp.StatusCode)
	}
	return nil
}

// createContainer creates a container from an image with the installer policy
// applied server-side (limits, read-only rootfs, dropped caps, no-new-privs).
func (c *dockerClient) createContainer(ctx context.Context, spec ContainerSpec, hmacDir string) (string, error) {
	env := make([]string, 0, len(spec.Env))
	for k, v := range spec.Env {
		env = append(env, k+"="+v)
	}
	name := spec.ContainerName + "-" + shortID()
	aliases := []string{name}
	for _, alias := range spec.NetworkAliases {
		if alias != "" {
			aliases = append(aliases, alias)
		}
	}
	body := map[string]any{
		"Image": spec.ImageTag,
		"Env":   env,
		"ExposedPorts": map[string]any{
			fmt.Sprintf("%d/tcp", spec.InternalPort): map[string]any{},
		},
		// Give the container the manifest's upstream hostname as a network
		// alias so services on the tool network can resolve it.
		"NetworkingConfig": map[string]any{
			"EndpointsConfig": map[string]any{
				spec.Network: map[string]any{
					"Aliases": aliases,
				},
			},
		},
		"HostConfig": map[string]any{
			"NetworkMode":    spec.Network,
			"ReadonlyRootfs": true,
			"Tmpfs":          map[string]string{"/tmp": "rw,noexec,nosuid,size=256m"},
			"CapDrop":        []string{"ALL"},
			"SecurityOpt":    []string{"no-new-privileges:true"},
			"Memory":         int64(spec.MemoryLimitMiB) * 1024 * 1024,
			"NanoCpus":       int64(spec.CPULimit * 1e9),
			"PidsLimit":      int64(spec.PidsLimit),
			"Binds":          []string{hmacDir + ":/run/secrets/tool-hmac:ro"},
			"RestartPolicy": map[string]any{
				"Name": "unless-stopped",
			},
		},
	}
	payload, _ := json.Marshal(body)
	query := url.Values{}
	query.Set("name", name)
	resp, err := c.do(ctx, http.MethodPost, "/v1.43/containers/create?"+query.Encode(), strings.NewReader(string(payload)), "application/json")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("create status %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	var out struct {
		ID string `json:"Id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	return name, nil
}

func (c *dockerClient) startContainer(ctx context.Context, name string) error {
	resp, err := c.do(ctx, http.MethodPost, "/v1.43/containers/"+url.PathEscape(name)+"/start", nil, "")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("start status %d", resp.StatusCode)
	}
	return nil
}

func (c *dockerClient) stopContainer(ctx context.Context, name string) error {
	resp, err := c.do(ctx, http.MethodPost, "/v1.43/containers/"+url.PathEscape(name)+"/stop?t=10", nil, "")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return nil
}

func (c *dockerClient) removeContainer(ctx context.Context, name string) error {
	resp, err := c.do(ctx, http.MethodDelete, "/v1.43/containers/"+url.PathEscape(name)+"?force=1&v=1", nil, "")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return nil
}

// containerHealth returns the Docker health status string ("healthy",
// "unhealthy", "starting", or "" when no healthcheck is defined).
func (c *dockerClient) containerHealth(ctx context.Context, name string) (string, error) {
	resp, err := c.do(ctx, http.MethodGet, "/v1.43/containers/"+url.PathEscape(name)+"/json", nil, "")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("inspect status %d", resp.StatusCode)
	}
	var out struct {
		State struct {
			Running bool `json:"Running"`
			Health  *struct {
				Status string `json:"Status"`
			} `json:"Health"`
		} `json:"State"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	if !out.State.Running {
		return "", nil
	}
	if out.State.Health == nil {
		return "none", nil
	}
	return out.State.Health.Status, nil
}

// tarContext writes the build context directory into a tar stream suitable for
// the build endpoint.
func tarContext(dir string) (io.Reader, error) {
	pr, pw := io.Pipe()
	go func() {
		tw := tar.NewWriter(pw)
		walkErr := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(dir, path)
			if err != nil {
				return err
			}
			if rel == "." {
				return nil
			}
			hdr, err := tar.FileInfoHeader(info, "")
			if err != nil {
				return err
			}
			hdr.Name = filepath.ToSlash(rel)
			if err := tw.WriteHeader(hdr); err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}
			f, err := os.Open(path)
			if err != nil {
				return err
			}
			_, err = io.Copy(tw, f)
			f.Close()
			return err
		})
		if walkErr != nil {
			tw.Close()
			pw.CloseWithError(walkErr)
			return
		}
		if err := tw.Close(); err != nil {
			pw.CloseWithError(err)
			return
		}
		pw.Close()
	}()
	return pr, nil
}

var idCounter = 0

// shortID returns a short unique suffix for container names.
func shortID() string {
	idCounter++
	return fmt.Sprintf("%d%d", time.Now().UnixNano()%1e9, idCounter%1000)
}
