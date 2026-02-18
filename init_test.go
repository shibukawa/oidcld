package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitCmdRun_GeneratesConfigFileWithTemplate(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "oidcld.yaml")

	cmd := InitCmd{
		Config:   configPath,
		Template: "standard",
	}

	if err := cmd.Run(); err != nil {
		t.Fatalf("Run() returned error: %v", err)
	}

	content, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("failed to read generated config: %v", err)
	}

	if len(content) == 0 {
		t.Fatalf("generated config is empty")
	}

	if !strings.Contains(string(content), `iss: "http://localhost:18888"`) {
		t.Fatalf("generated config does not contain standard issuer")
	}
}

func TestInitCmdRun_ReturnsErrorWhenConfigExistsWithoutOverwrite(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "oidcld.yaml")

	if err := os.WriteFile(configPath, []byte("existing"), 0644); err != nil {
		t.Fatalf("failed to prepare existing config: %v", err)
	}

	cmd := InitCmd{
		Config:   configPath,
		Template: "standard",
	}

	err := cmd.Run()
	if err == nil {
		t.Fatalf("expected error when config exists without overwrite")
	}

	if !strings.Contains(err.Error(), ErrFilesExist.Error()) {
		t.Fatalf("unexpected error: %v", err)
	}
}
