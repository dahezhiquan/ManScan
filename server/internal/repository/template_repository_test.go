package repository

import (
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
