package supplychain

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGetDefaultCacheDir_EnvVar(t *testing.T) {
	// Set env var
	customDir := "/custom/cache/dir"
	t.Setenv("SUPPLYSCAN_CACHE_DIR", customDir)

	dir, err := getDefaultCacheDir()
	if err != nil {
		t.Fatalf("getDefaultCacheDir() error = %v", err)
	}

	if dir != customDir {
		t.Errorf("getDefaultCacheDir() = %q, want %q", dir, customDir)
	}
}

func TestGetDefaultCacheDir_EnvVarTakesPriority(t *testing.T) {
	// Even if /cache exists, env var should take priority
	customDir := "/custom/priority/dir"
	t.Setenv("SUPPLYSCAN_CACHE_DIR", customDir)

	dir, err := getDefaultCacheDir()
	if err != nil {
		t.Fatalf("getDefaultCacheDir() error = %v", err)
	}

	if dir != customDir {
		t.Errorf("getDefaultCacheDir() = %q, want %q (env var should take priority)", dir, customDir)
	}
}

func TestGetDefaultCacheDir_DockerCache(t *testing.T) {
	// Ensure env var is not set
	t.Setenv("SUPPLYSCAN_CACHE_DIR", "")

	// Check if /cache exists on this system
	if info, err := os.Stat("/cache"); err == nil && info.IsDir() {
		dir, err := getDefaultCacheDir()
		if err != nil {
			t.Fatalf("getDefaultCacheDir() error = %v", err)
		}

		if dir != "/cache" {
			t.Errorf("getDefaultCacheDir() = %q, want /cache when /cache directory exists", dir)
		}
	} else {
		t.Skip("Skipping: /cache directory does not exist on this system")
	}
}

func TestGetDefaultCacheDir_FallbackHome(t *testing.T) {
	// Ensure env var is not set
	t.Setenv("SUPPLYSCAN_CACHE_DIR", "")

	// Skip if /cache exists (would take priority)
	if info, err := os.Stat("/cache"); err == nil && info.IsDir() {
		t.Skip("Skipping: /cache directory exists, would take priority over home fallback")
	}

	dir, err := getDefaultCacheDir()
	if err != nil {
		t.Fatalf("getDefaultCacheDir() error = %v", err)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("os.UserHomeDir() error = %v", err)
	}

	expected := filepath.Join(home, ".cache", "supplyscan-mcp")
	if dir != expected {
		t.Errorf("getDefaultCacheDir() = %q, want %q", dir, expected)
	}
}

func TestGetDefaultCacheDir_Priority(t *testing.T) {
	// Test the full priority chain by creating a temp /cache-like dir
	// and verifying env var still wins

	tmpDir := t.TempDir()
	customEnvDir := filepath.Join(tmpDir, "env-cache")

	t.Setenv("SUPPLYSCAN_CACHE_DIR", customEnvDir)

	dir, err := getDefaultCacheDir()
	if err != nil {
		t.Fatalf("getDefaultCacheDir() error = %v", err)
	}

	if dir != customEnvDir {
		t.Errorf("getDefaultCacheDir() = %q, want %q (env var has highest priority)", dir, customEnvDir)
	}
}
