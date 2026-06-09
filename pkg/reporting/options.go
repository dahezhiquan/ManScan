package reporting

import (
	"ManScan/pkg/output"
	"ManScan/pkg/reporting/exporters/es"
	"ManScan/pkg/reporting/exporters/jsonexporter"
	"ManScan/pkg/reporting/exporters/jsonl"
	"ManScan/pkg/reporting/exporters/markdown"
	"ManScan/pkg/reporting/exporters/mongo"
	"ManScan/pkg/reporting/exporters/pdf"
	"ManScan/pkg/reporting/exporters/sarif"
	"ManScan/pkg/reporting/exporters/splunk"
	"ManScan/pkg/reporting/trackers/filters"
	"ManScan/pkg/reporting/trackers/gitea"
	"ManScan/pkg/reporting/trackers/github"
	"ManScan/pkg/reporting/trackers/gitlab"
	"ManScan/pkg/reporting/trackers/jira"
	"ManScan/pkg/reporting/trackers/linear"
	"github.com/projectdiscovery/retryablehttp-go"
)

// Options is a configuration file for nuclei reporting module
type Options struct {
	// AllowList contains a list of allowed events for reporting module
	AllowList *filters.Filter `yaml:"allow-list"`
	// DenyList contains a list of denied events for reporting module
	DenyList *filters.Filter `yaml:"deny-list"`
	// ValidatorCallback is a callback function that is called to validate an event before it is reported
	ValidatorCallback func(event *output.ResultEvent) bool `yaml:"-"`
	// GitHub contains configuration options for GitHub Issue Tracker
	GitHub *github.Options `yaml:"github"`
	// GitLab contains configuration options for GitLab Issue Tracker
	GitLab *gitlab.Options `yaml:"gitlab"`
	// Gitea contains configuration options for Gitea Issue Tracker
	Gitea *gitea.Options `yaml:"gitea"`
	// Jira contains configuration options for Jira Issue Tracker
	Jira *jira.Options `yaml:"jira"`
	// Linear contains configuration options for Linear Issue Tracker
	Linear *linear.Options `yaml:"linear"`
	// MarkdownExporter contains configuration options for Markdown Exporter Module
	MarkdownExporter *markdown.Options `yaml:"markdown"`
	// SarifExporter contains configuration options for Sarif Exporter Module
	SarifExporter *sarif.Options `yaml:"sarif"`
	// ElasticsearchExporter contains configuration options for Elasticsearch Exporter Module
	ElasticsearchExporter *es.Options `yaml:"elasticsearch"`
	// SplunkExporter contains configuration options for splunkhec Exporter Module
	SplunkExporter *splunk.Options `yaml:"splunkhec"`
	// JSONExporter contains configuration options for JSON Exporter Module
	JSONExporter *jsonexporter.Options `yaml:"json"`
	// JSONLExporter contains configuration options for JSONL Exporter Module
	JSONLExporter *jsonl.Options `yaml:"jsonl"`
	// PDFExporter contains configuration options for PDF Exporter Module
	PDFExporter *pdf.Options `yaml:"pdf"`
	// MongoDBExporter containers the configuration options for the MongoDB Exporter Module
	MongoDBExporter *mongo.Options `yaml:"mongodb"`

	HttpClient *retryablehttp.Client `yaml:"-"`
	OmitRaw    bool                  `yaml:"-"`

	ExecutionId string `yaml:"-"`
}
