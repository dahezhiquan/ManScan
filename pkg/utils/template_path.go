package utils

import (
	"path/filepath"

	"ManScan/pkg/catalog/config"
	"ManScan/pkg/keys"
	filepathutil "ManScan/pkg/utils/filepath"
)

const (
	// TemplatesRepoURL is the URL for files in nuclei-templates repository
	TemplatesRepoURL = "https://cloud.projectdiscovery.io/public/"
)

// TemplatePathURL returns the Path and URL for the provided template
func TemplatePathURL(fullPath, templateId, templateVerifier string) (path string, url string) {
	configData := config.DefaultConfig
	if configData.TemplatesDirectory != "" && filepathutil.IsPathWithinDirectory(fullPath, configData.GetTemplateDir()) {
		relPath, err := filepath.Rel(configData.GetTemplateDir(), fullPath)
		if err == nil && relPath != "." {
			path = relPath
		}
	}
	if templateVerifier == keys.PDVerifier {
		url = TemplatesRepoURL + templateId
	}
	return
}
