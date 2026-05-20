// SPDX-License-Identifier: MIT
// © 2026 HostAtlas Technologies LLC
// hello@hostatlas.app

package updater

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// extractTarGz extracts a .tar.gz archive into the destination directory.
// It only extracts regular files and skips any paths that would escape the
// destination (zip-slip protection).
func extractTarGz(archivePath, destDir string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return fmt.Errorf("opening archive: %w", err)
	}
	defer f.Close()

	gzr, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("creating gzip reader: %w", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("reading tar entry: %w", err)
		}

		// Only extract regular files.
		if header.Typeflag != tar.TypeReg {
			continue
		}

		// Sanitize the path to prevent zip-slip.
		cleanName := filepath.Clean(header.Name)
		if strings.Contains(cleanName, "..") {
			continue
		}

		// Use only the base name — goreleaser archives may nest files
		// inside a directory.
		baseName := filepath.Base(cleanName)
		destPath := filepath.Join(destDir, baseName)

		outFile, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(header.Mode))
		if err != nil {
			return fmt.Errorf("creating %s: %w", destPath, err)
		}

		// Limit copy size to 256MB to prevent resource exhaustion.
		if _, err := io.Copy(outFile, io.LimitReader(tr, 256<<20)); err != nil {
			outFile.Close()
			return fmt.Errorf("extracting %s: %w", destPath, err)
		}
		outFile.Close()
	}

	return nil
}
