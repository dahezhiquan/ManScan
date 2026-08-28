package repository

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	config "ManScan/pkg/catalog/config"
	"ManScan/pkg/model"
	modelstringslice "ManScan/pkg/model/types/stringslice"
	"ManScan/server/internal/model/dto"

	fileutil "github.com/projectdiscovery/utils/file"
	"gopkg.in/yaml.v2"
)

const (
	templateListPageSize = 20
	templateCacheTTL     = 12 * time.Hour
)

type TemplateRepository interface {
	List() ([]dto.TemplateListItem, error)
	FindByID(templateID string) (*dto.TemplateDetail, error)
	Tags() ([]string, error)
	Protocols() ([]string, error)
	Stats() (*dto.TemplateStats, error)
}

type templateRepository struct {
	rootDir string
	cache   *templateCache
}

type templateCache struct {
	mu        sync.RWMutex
	rootDir   string
	expiresAt time.Time
	items     []templateListRecord
	index     map[string]string
	stats     dto.TemplateStats
}

type templateMetadata struct {
	ID                  string        `yaml:"id"`
	Info                model.Info    `yaml:"info"`
	RequestsHTTP        []interface{} `yaml:"requests"`
	RequestsWithHTTP    []interface{} `yaml:"http"`
	RequestsDNS         []interface{} `yaml:"dns"`
	RequestsFile        []interface{} `yaml:"file"`
	RequestsNetwork     []interface{} `yaml:"network"`
	RequestsWithTCP     []interface{} `yaml:"tcp"`
	RequestsHeadless    []interface{} `yaml:"headless"`
	RequestsJavaScript  []interface{} `yaml:"javascript"`
	RequestsWebsocket   []interface{} `yaml:"websocket"`
	RequestsWhois       []interface{} `yaml:"whois"`
	RequestsOfflineHTTP []interface{} `yaml:"offlinehttp"`
	RequestsSSL         []interface{} `yaml:"ssl"`
	RequestsCode        []interface{} `yaml:"code"`
	Workflows           []interface{} `yaml:"workflows"`
}

type templateListRecord struct {
	dto.TemplateListItem
	Path string
}

func NewTemplateRepository(rootDir string) TemplateRepository {
	return &templateRepository{
		rootDir: rootDir,
		cache:   &templateCache{},
	}
}

func (r *templateRepository) List() ([]dto.TemplateListItem, error) {
	records, _, _, err := r.loadIndex()
	if err != nil {
		return nil, err
	}

	items := make([]dto.TemplateListItem, 0, len(records))
	for _, record := range records {
		items = append(items, record.TemplateListItem)
	}
	return items, nil
}

func (r *templateRepository) FindByID(templateID string) (*dto.TemplateDetail, error) {
	_, index, _, err := r.loadIndex()
	if err != nil {
		return nil, err
	}

	templatePath := index[strings.TrimSpace(templateID)]
	if templatePath == "" {
		return nil, nil
	}

	data, err := os.ReadFile(templatePath)
	if err != nil {
		return nil, err
	}

	doc, err := parseTemplateMetadataBytes(data)
	if err != nil {
		return nil, err
	}

	info := doc.Info
	return &dto.TemplateDetail{
		ID:          strings.TrimSpace(doc.ID),
		Protocols:   collectTemplateProtocols(doc),
		Name:        strings.TrimSpace(info.Name),
		Tags:        safeNormalizedTags(info.Tags),
		Severity:    safeSeverityText(info),
		Description: strings.TrimSpace(info.Description),
		Impact:      strings.TrimSpace(info.Impact),
		Remediation: strings.TrimSpace(info.Remediation),
		Reference:   normalizeReferenceList(info.Reference),
		CVSSScore:   safeCVSSScore(info),
		Vendor:      getMetadataString(info.Metadata, "vendor"),
		Product:     getMetadataString(info.Metadata, "product"),
		ShodanQuery: getMetadataStringList(info.Metadata, "shodan-query"),
		FofaQuery:   getMetadataStringList(info.Metadata, "fofa-query"),
		Content:     string(data),
	}, nil
}

func (r *templateRepository) Tags() ([]string, error) {
	items, err := r.List()
	if err != nil {
		return nil, err
	}
	return collectSortedUniqueTemplateFieldValues(items, func(item dto.TemplateListItem) []string {
		return item.Tags
	}), nil
}

func (r *templateRepository) Protocols() ([]string, error) {
	items, err := r.List()
	if err != nil {
		return nil, err
	}
	return collectSortedUniqueTemplateFieldValues(items, func(item dto.TemplateListItem) []string {
		return item.Protocols
	}), nil
}

func (r *templateRepository) Stats() (*dto.TemplateStats, error) {
	_, _, stats, err := r.loadIndex()
	if err != nil {
		return nil, err
	}
	copyStats := stats
	return &copyStats, nil
}

func (r *templateRepository) loadIndex() ([]templateListRecord, map[string]string, dto.TemplateStats, error) {
	rootDir := strings.TrimSpace(r.rootDir)
	if rootDir == "" {
		rootDir = strings.TrimSpace(config.DefaultConfig.GetTemplateDir())
	}
	if rootDir == "" {
		rootDir = config.DefaultConfig.TemplatesDirectory
	}

	if cachedItems, cachedIndex, cachedStats, ok := r.cache.get(rootDir); ok {
		return cachedItems, cachedIndex, cachedStats, nil
	}

	if !fileutil.FolderExists(rootDir) {
		r.cache.set(rootDir, nil, map[string]string{}, dto.TemplateStats{})
		return nil, map[string]string{}, dto.TemplateStats{}, nil
	}

	records := make([]templateListRecord, 0, 1024)
	index := make(map[string]string, 1024)
	stats := dto.TemplateStats{}

	err := filepath.WalkDir(rootDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil || d.IsDir() {
			return nil
		}
		if !config.IsTemplateWithRoot(path, rootDir) {
			return nil
		}

		doc, err := parseTemplateMetadata(path)
		if err != nil {
			return nil
		}

		record := templateListRecord{
			TemplateListItem: dto.TemplateListItem{
				ID:          strings.TrimSpace(doc.ID),
				Name:        strings.TrimSpace(doc.Info.Name),
				Description: truncateDescription(doc.Info.Description, 50),
				Severity:    mapSeverityText(doc.Info.SeverityHolder.Severity.String()),
				Author:      doc.Info.Authors.String(),
				Protocols:   collectTemplateProtocols(doc),
				Tags:        normalizeTemplateTags(doc.Info.Tags.ToSlice()),
			},
			Path: path,
		}
		records = append(records, record)

		if record.ID != "" {
			if existingPath, ok := index[record.ID]; !ok || path < existingPath {
				index[record.ID] = path
			}
		}

		stats.TemplateCount++
		if hasAnyTemplateTag(doc, newTemplateTagSet("kev")) {
			stats.KEVTemplateCount++
		}
		if hasAnyTemplateTag(doc, newTemplateTagSet("cve")) {
			stats.CVETemplateCount++
		}
		if hasAnyTemplateTag(doc, newTemplateTagSet("tech")) {
			stats.FingerprintTemplateCount++
		}

		return nil
	})
	if err != nil {
		return nil, nil, dto.TemplateStats{}, err
	}

	sort.Slice(records, func(i, j int) bool {
		if records[i].ID != records[j].ID {
			return records[i].ID < records[j].ID
		}
		if records[i].Name != records[j].Name {
			return records[i].Name < records[j].Name
		}
		return records[i].Path < records[j].Path
	})

	r.cache.set(rootDir, records, index, stats)
	return cloneTemplateRecords(records), cloneTemplateIndex(index), stats, nil
}

func parseTemplateMetadata(path string) (*templateMetadata, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseTemplateMetadataBytes(data)
}

func parseTemplateMetadataBytes(data []byte) (*templateMetadata, error) {
	var doc templateMetadata
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	return &doc, nil
}

func normalizeReferenceList(reference *modelstringslice.RawStringSlice) []string {
	defer func() { _ = recover() }()
	if reference == nil {
		return []string{}
	}

	values := reference.ToSlice()
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		for _, item := range splitReferenceItems(value) {
			if item == "" || containsString(normalized, item) {
				continue
			}
			normalized = append(normalized, item)
		}
	}
	return normalized
}

func splitReferenceItems(value string) []string {
	normalized := strings.ReplaceAll(value, "\r\n", "\n")
	parts := strings.Split(normalized, "\n")
	items := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(part), "- "), "-"))
		if trimmed != "" {
			items = append(items, trimmed)
		}
	}
	if len(items) > 0 {
		return items
	}

	items = splitMetadataListByDash(value)
	if len(items) > 0 {
		return items
	}
	return []string{strings.TrimSpace(value)}
}

func splitMetadataListByDash(value string) []string {
	replaced := strings.ReplaceAll(value, " - ", "\n- ")
	if !strings.Contains(replaced, "- ") {
		return nil
	}

	result := make([]string, 0)
	for _, line := range strings.Split(replaced, "\n") {
		line = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "- "))
		if line != "" {
			result = append(result, line)
		}
	}
	return result
}

func safeNormalizedTags(tags modelstringslice.StringSlice) (result []string) {
	defer func() {
		if recover() != nil {
			result = []string{}
		}
	}()
	return normalizeTemplateTags(tags.ToSlice())
}

func safeSeverityText(info model.Info) (result string) {
	defer func() {
		if recover() != nil {
			result = ""
		}
	}()
	return mapSeverityText(info.SeverityHolder.Severity.String())
}

func safeCVSSScore(info model.Info) float64 {
	if info.Classification == nil {
		return 0
	}
	return info.Classification.CVSSScore
}

func getMetadataStringList(metadata map[string]interface{}, key string) []string {
	if len(metadata) == 0 {
		return []string{}
	}
	value, ok := metadata[key]
	if !ok {
		return []string{}
	}
	return normalizeMetadataListValue(value)
}

func normalizeMetadataListValue(value interface{}) []string {
	switch typed := value.(type) {
	case []string:
		return cleanStringSlice(typed)
	case []interface{}:
		result := make([]string, 0, len(typed))
		for _, item := range typed {
			text := stringifyMetadataValue(item)
			if text != "" {
				result = append(result, text)
			}
		}
		return result
	case string:
		return splitReferenceItems(typed)
	default:
		text := stringifyMetadataValue(value)
		if text == "" {
			return []string{}
		}
		return []string{text}
	}
}

func getMetadataString(metadata map[string]interface{}, key string) string {
	if len(metadata) == 0 {
		return ""
	}
	return stringifyMetadataValue(metadata[key])
}

func stringifyMetadataValue(value interface{}) string {
	if value == nil {
		return ""
	}
	if text, ok := value.(string); ok {
		return strings.TrimSpace(text)
	}
	return strings.TrimSpace(fmt.Sprint(value))
}

func collectSortedUniqueTemplateFieldValues(items []dto.TemplateListItem, extractor func(dto.TemplateListItem) []string) []string {
	unique := make(map[string]struct{}, len(items))
	for _, item := range items {
		for _, value := range extractor(item) {
			if value != "" {
				unique[value] = struct{}{}
			}
		}
	}

	result := make([]string, 0, len(unique))
	for value := range unique {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func collectTemplateProtocols(doc *templateMetadata) []string {
	protocols := make([]string, 0, 8)
	fields := []struct {
		name  string
		count int
	}{
		{name: "http", count: len(doc.RequestsHTTP) + len(doc.RequestsWithHTTP)},
		{name: "dns", count: len(doc.RequestsDNS)},
		{name: "file", count: len(doc.RequestsFile)},
		{name: "network", count: len(doc.RequestsNetwork) + len(doc.RequestsWithTCP)},
		{name: "headless", count: len(doc.RequestsHeadless)},
		{name: "javascript", count: len(doc.RequestsJavaScript)},
		{name: "websocket", count: len(doc.RequestsWebsocket)},
		{name: "whois", count: len(doc.RequestsWhois)},
		{name: "offlinehttp", count: len(doc.RequestsOfflineHTTP)},
		{name: "ssl", count: len(doc.RequestsSSL)},
		{name: "code", count: len(doc.RequestsCode)},
	}

	for _, field := range fields {
		if field.count > 0 {
			protocols = append(protocols, field.name)
		}
	}
	if len(doc.Workflows) > 0 {
		protocols = append(protocols, "workflow")
	}
	sort.Strings(protocols)
	return protocols
}

func truncateDescription(value string, limit int) string {
	value = strings.TrimSpace(value)
	runes := []rune(value)
	if len(runes) <= limit || limit <= 0 {
		return value
	}
	return strings.TrimSpace(string(runes[:limit])) + "..."
}

func mapSeverityText(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	case "info", "informational":
		return "info"
	default:
		return ""
	}
}

func normalizeTemplateTags(tags []string) []string {
	result := make([]string, 0, len(tags))
	for _, tag := range tags {
		for _, item := range splitCommaTrim(tag) {
			if item != "" && !containsString(result, item) {
				result = append(result, item)
			}
		}
	}
	sort.Strings(result)
	return result
}

func splitCommaTrim(value string) []string {
	if !strings.Contains(value, ",") {
		text := strings.ToLower(strings.TrimSpace(value))
		if text == "" {
			return []string{}
		}
		return []string{text}
	}
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		text := strings.ToLower(strings.TrimSpace(part))
		if text != "" {
			result = append(result, text)
		}
	}
	return result
}

type templateTagSet map[string]struct{}

func newTemplateTagSet(tags ...string) templateTagSet {
	result := make(templateTagSet, len(tags))
	for _, tag := range tags {
		for _, normalized := range splitCommaTrim(tag) {
			if normalized != "" {
				result[normalized] = struct{}{}
			}
		}
	}
	return result
}

func hasAnyTemplateTag(doc *templateMetadata, expectedTags templateTagSet) bool {
	if doc == nil || len(expectedTags) == 0 {
		return false
	}
	for _, templateTag := range doc.Info.Tags.ToSlice() {
		for _, normalized := range splitCommaTrim(templateTag) {
			if _, ok := expectedTags[normalized]; ok {
				return true
			}
		}
	}
	return false
}

func cleanStringSlice(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func containsString(items []string, target string) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}

func cloneTemplateRecords(items []templateListRecord) []templateListRecord {
	cloned := make([]templateListRecord, len(items))
	copy(cloned, items)
	return cloned
}

func cloneTemplateIndex(index map[string]string) map[string]string {
	cloned := make(map[string]string, len(index))
	for key, value := range index {
		cloned[key] = value
	}
	return cloned
}

func (c *templateCache) get(rootDir string) ([]templateListRecord, map[string]string, dto.TemplateStats, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.rootDir != rootDir || time.Now().After(c.expiresAt) {
		return nil, nil, dto.TemplateStats{}, false
	}
	return cloneTemplateRecords(c.items), cloneTemplateIndex(c.index), c.stats, true
}

func (c *templateCache) set(rootDir string, items []templateListRecord, index map[string]string, stats dto.TemplateStats) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rootDir = rootDir
	c.expiresAt = time.Now().Add(templateCacheTTL)
	c.items = cloneTemplateRecords(items)
	c.index = cloneTemplateIndex(index)
	c.stats = stats
}

func _() {
	_ = reflect.TypeOf(nil)
	_ = templateListPageSize
}
