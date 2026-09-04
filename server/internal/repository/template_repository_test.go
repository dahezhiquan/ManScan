package repository

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestCollectTemplateProtocolsUsesTopLevelExecutionBlockKeys(t *testing.T) {
	t.Parallel()

	doc, err := parseTemplateMetadataBytes([]byte(`
id: top-level-only
info:
  name: Top Level Only
  severity: info
variables:
  protocol_word: tcp
matchers:
  - type: word
    words:
      - dns
# ssl:
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
`))
	if err != nil {
		t.Fatalf("parseTemplateMetadataBytes() error = %v", err)
	}

	got := collectTemplateProtocols(doc)
	want := []string{"http"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("collectTemplateProtocols() = %v, want %v", got, want)
	}
}

func TestCollectTemplateProtocolsUsesWhitelistAliases(t *testing.T) {
	t.Parallel()

	doc, err := parseTemplateMetadataBytes([]byte(`
id: aliases
info:
  name: Aliases
  severity: info
requests:
  - method: GET
    path:
      - "{{BaseURL}}/"
network:
  - inputs:
      - data: test
tcp:
  - inputs:
      - data: test
workflows:
  - template: http/example.yaml
`))
	if err != nil {
		t.Fatalf("parseTemplateMetadataBytes() error = %v", err)
	}

	got := collectTemplateProtocols(doc)
	want := []string{"http", "tcp", "workflows"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("collectTemplateProtocols() = %v, want %v", got, want)
	}
}

func TestTemplateRepositoryStatsCountsFingerprintTagsFromTechDetectAndFavicon(t *testing.T) {
	t.Parallel()

	rootDir := t.TempDir()
	templates := map[string]string{
		"tech.yaml": `id: tech-only
info:
  name: Tech Only
  severity: info
  tags: tech,platform
`,
		"detect.yaml": `id: detect-only
info:
  name: Detect Only
  severity: info
  tags: detect,platform
`,
		"favicon.yaml": `id: favicon-only
info:
  name: Favicon Only
  severity: info
  tags: favicon,platform
`,
		"mixed.yaml": `id: mixed-tech-detect
info:
  name: Mixed Tech Detect
  severity: info
  tags: tech,detect,platform
`,
		"plain.yaml": `id: plain-template
info:
  name: Plain Template
  severity: info
  tags: platform
`,
	}

	for fileName, content := range templates {
		path := filepath.Join(rootDir, fileName)
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("WriteFile(%s) error = %v", fileName, err)
		}
	}

	repo := NewTemplateRepository(rootDir)
	stats, err := repo.Stats()
	if err != nil {
		t.Fatalf("Stats() error = %v", err)
	}
	if stats.TemplateCount != len(templates) {
		t.Fatalf("TemplateCount = %d, want %d", stats.TemplateCount, len(templates))
	}
	if stats.FingerprintTemplateCount != 4 {
		t.Fatalf("FingerprintTemplateCount = %d, want 4", stats.FingerprintTemplateCount)
	}
}
