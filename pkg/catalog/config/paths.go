package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func defaultConfigDir() string {
	return DefaultConfigDir()
}

func defaultStateDir() string {
	return DefaultConfigDir()
}

func defaultCacheDir() string {
	return DefaultCacheDir()
}

func selectXDGTemplateRoot(dataHome string, dataDirs []string) (string, error) {
	if !filepath.IsAbs(dataHome) {
		return "", fmt.Errorf("XDG data home %q is not absolute", dataHome)
	}

	userRoot := filepath.Join(dataHome, BinaryName, NucleiTemplatesDirName)
	exists, err := directoryExists(userRoot)
	if err != nil {
		return "", err
	}

	if exists {
		return userRoot, nil
	}

	for _, dataDir := range dataDirs {
		if !filepath.IsAbs(dataDir) {
			continue
		}

		root := filepath.Join(dataDir, BinaryName, NucleiTemplatesDirName)
		exists, err := directoryExists(root)
		if err != nil {
			return "", err
		}

		if exists {
			return root, nil
		}
	}

	return userRoot, nil
}

func directoryExists(path string) (bool, error) {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}

	if err != nil {
		return false, fmt.Errorf("inspect directory %q: %w", path, err)
	}

	if !info.IsDir() {
		return false, fmt.Errorf("path %q is not a directory", path)
	}

	return true, nil
}
