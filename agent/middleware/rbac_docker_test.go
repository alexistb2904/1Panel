package middleware

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/1Panel-dev/1Panel/agent/app/dto"
)

func TestRestrictedContainerRejectsPrivileged(t *testing.T) {
	err := validateRestrictedContainer(dto.ContainerOperate{Privileged: true}, "")
	if err == nil {
		t.Fatal("privileged container must be rejected")
	}
}

func TestRestrictedContainerAllowsBindInsideProjectRoot(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "data")
	if err := os.Mkdir(source, 0o755); err != nil {
		t.Fatal(err)
	}
	req := dto.ContainerOperate{Volumes: []dto.VolumeHelper{{Type: "bind", SourceDir: source, ContainerDir: "/data"}}}
	if err := validateRestrictedContainer(req, root); err != nil {
		t.Fatalf("safe project bind should be allowed: %v", err)
	}
}

func TestRestrictedContainerRejectsBindOutsideProjectRoot(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	req := dto.ContainerOperate{Volumes: []dto.VolumeHelper{{Type: "bind", SourceDir: outside, ContainerDir: "/host"}}}
	if err := validateRestrictedContainer(req, root); err == nil {
		t.Fatal("bind outside project root must be rejected")
	}
}

func TestRestrictedContainerRejectsSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	link := filepath.Join(root, "escape")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	req := dto.ContainerOperate{Volumes: []dto.VolumeHelper{{Type: "bind", SourceDir: link, ContainerDir: "/host"}}}
	if err := validateRestrictedContainer(req, root); err == nil {
		t.Fatal("symlink escaping project root must be rejected")
	}
}

func TestRestrictedContainerRejectsExistingNamedVolume(t *testing.T) {
	req := dto.ContainerOperate{Volumes: []dto.VolumeHelper{{Type: "volume", SourceDir: "shared-production-data", ContainerDir: "/data"}}}
	if err := validateRestrictedContainer(req, ""); err == nil {
		t.Fatal("existing named volume must be administrator-only")
	}
}

func TestRestrictedComposeAllowsSimpleProjectStack(t *testing.T) {
	compose := `services:
  web:
    image: nginx:alpine
    ports:
      - "8080:80"
    restart: unless-stopped
`
	if err := validateRestrictedCompose(compose, ""); err != nil {
		t.Fatalf("simple image-based Compose should be allowed: %v", err)
	}
}

func TestRestrictedComposeRejectsPrivileged(t *testing.T) {
	compose := `services:
  app:
    image: alpine
    privileged: true
`
	if err := validateRestrictedCompose(compose, ""); err == nil {
		t.Fatal("privileged Compose service must be rejected")
	}
}

func TestRestrictedComposeRejectsHostNetwork(t *testing.T) {
	compose := `services:
  app:
    image: alpine
    network_mode: host
`
	if err := validateRestrictedCompose(compose, ""); err == nil {
		t.Fatal("host network must be rejected")
	}
}

func TestRestrictedComposeRejectsCapabilities(t *testing.T) {
	compose := `services:
  app:
    image: alpine
    cap_add:
      - SYS_ADMIN
`
	if err := validateRestrictedCompose(compose, ""); err == nil {
		t.Fatal("cap_add must be rejected")
	}
}

func TestRestrictedComposeRejectsExternalVolume(t *testing.T) {
	compose := `services:
  app:
    image: alpine
    volumes:
      - production:/data
volumes:
  production:
    external: true
`
	if err := validateRestrictedCompose(compose, ""); err == nil {
		t.Fatal("external Compose volume must be rejected")
	}
}

func TestRestrictedComposeRejectsExternalNetwork(t *testing.T) {
	compose := `services:
  app:
    image: alpine
    networks:
      - production
networks:
  production:
    external: true
`
	if err := validateRestrictedCompose(compose, ""); err == nil {
		t.Fatal("external Compose network must be rejected")
	}
}

func TestRestrictedComposeRejectsDockerSocketBind(t *testing.T) {
	root := t.TempDir()
	compose := `services:
  app:
    image: alpine
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
`
	if err := validateRestrictedCompose(compose, root); err == nil {
		t.Fatal("Docker socket bind outside project root must be rejected")
	}
}

func TestRestrictedComposeAllowsBindInsideProjectRoot(t *testing.T) {
	root := t.TempDir()
	data := filepath.Join(root, "data")
	if err := os.Mkdir(data, 0o755); err != nil {
		t.Fatal(err)
	}
	compose := "services:\n  app:\n    image: alpine\n    volumes:\n      - " + data + ":/data\n"
	if err := validateRestrictedCompose(compose, root); err != nil {
		t.Fatalf("bind below project root should be allowed: %v", err)
	}
}
