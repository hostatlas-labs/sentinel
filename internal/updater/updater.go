// SPDX-License-Identifier: MIT
// © 2026 HostAtlas Technologies LLC
// hello@hostatlas.app

package updater

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"
)

const (
	repoOwner = "akyroslabs"
	repoName  = "hostatlas-sentinel"
	apiURL    = "https://api.github.com/repos/" + repoOwner + "/" + repoName + "/releases/latest"
)

// Release represents a GitHub release.
type Release struct {
	TagName string  `json:"tag_name"`
	Assets  []Asset `json:"assets"`
}

// Asset represents a downloadable file in a GitHub release.
type Asset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

// Update checks for a newer release on GitHub and replaces the current binary
// if an update is available.
func Update(ctx context.Context, currentVersion string) error {
	client := &http.Client{Timeout: 30 * time.Second}

	// Fetch the latest release metadata.
	release, err := fetchLatestRelease(ctx, client)
	if err != nil {
		return fmt.Errorf("checking for updates: %w", err)
	}

	latestVersion := strings.TrimPrefix(release.TagName, "v")
	currentClean := strings.TrimPrefix(currentVersion, "v")

	if latestVersion == currentClean {
		fmt.Printf("Already up to date (v%s).\n", currentClean)
		return nil
	}

	// Find the matching asset for this platform.
	assetName := matchAssetName(runtime.GOOS, runtime.GOARCH)
	var downloadURL string
	for _, asset := range release.Assets {
		if asset.Name == assetName {
			downloadURL = asset.BrowserDownloadURL
			break
		}
	}
	if downloadURL == "" {
		return fmt.Errorf("no release asset found for %s/%s (expected %s)", runtime.GOOS, runtime.GOARCH, assetName)
	}

	fmt.Printf("Updating sentinel v%s -> v%s ...\n", currentClean, latestVersion)

	// Download the new binary.
	tmpPath, err := downloadAsset(ctx, client, downloadURL)
	if err != nil {
		return fmt.Errorf("downloading update: %w", err)
	}
	defer os.Remove(tmpPath)

	// Replace the current binary.
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locating current binary: %w", err)
	}

	if err := replaceBinary(tmpPath, execPath); err != nil {
		return fmt.Errorf("replacing binary: %w", err)
	}

	fmt.Printf("Updated to v%s successfully.\n", latestVersion)
	return nil
}

// fetchLatestRelease retrieves the latest release information from GitHub.
func fetchLatestRelease(ctx context.Context, client *http.Client) (*Release, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "hostatlas-sentinel-updater")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("GitHub API returned %d: %s", resp.StatusCode, string(body))
	}

	var release Release
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, fmt.Errorf("decoding release: %w", err)
	}

	return &release, nil
}

// matchAssetName constructs the expected release asset filename for the
// current platform, matching the goreleaser naming convention.
func matchAssetName(goos, goarch string) string {
	return fmt.Sprintf("sentinel_%s_%s.tar.gz", goos, goarch)
}

// downloadAsset downloads a release asset to a temporary file and returns
// the path.
func downloadAsset(ctx context.Context, client *http.Client, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "hostatlas-sentinel-updater")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download returned status %d", resp.StatusCode)
	}

	tmpFile, err := os.CreateTemp("", "sentinel-update-*.tar.gz")
	if err != nil {
		return "", fmt.Errorf("creating temp file: %w", err)
	}

	if _, err := io.Copy(tmpFile, resp.Body); err != nil {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		return "", fmt.Errorf("writing download: %w", err)
	}
	tmpFile.Close()

	return tmpFile.Name(), nil
}

// replaceBinary extracts the sentinel binary from the tarball and replaces
// the current executable.
func replaceBinary(tarballPath, destPath string) error {
	// Create a temporary directory for extraction.
	tmpDir, err := os.MkdirTemp("", "sentinel-extract-*")
	if err != nil {
		return fmt.Errorf("creating temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Extract the tarball.
	if err := extractTarGz(tarballPath, tmpDir); err != nil {
		return fmt.Errorf("extracting archive: %w", err)
	}

	// Find the sentinel binary in the extracted files.
	extractedBinary := tmpDir + "/sentinel"
	if _, err := os.Stat(extractedBinary); err != nil {
		return fmt.Errorf("sentinel binary not found in archive: %w", err)
	}

	// Read the new binary.
	newBinary, err := os.ReadFile(extractedBinary)
	if err != nil {
		return fmt.Errorf("reading extracted binary: %w", err)
	}

	// Get current binary permissions.
	info, err := os.Stat(destPath)
	if err != nil {
		return fmt.Errorf("stat current binary: %w", err)
	}

	// Write to a temporary file next to the target, then rename.
	tmpDest := destPath + ".new"
	if err := os.WriteFile(tmpDest, newBinary, info.Mode()); err != nil {
		return fmt.Errorf("writing new binary: %w", err)
	}

	if err := os.Rename(tmpDest, destPath); err != nil {
		os.Remove(tmpDest)
		return fmt.Errorf("renaming new binary: %w", err)
	}

	return nil
}
