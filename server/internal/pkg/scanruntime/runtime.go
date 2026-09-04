package scanruntime

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	DefaultLogPageSize = 200
	MaxLogPageSize     = 1000
	MaxSubscribers     = 32
)

var ansiLogPattern = regexp.MustCompile(`\x1b\[[0-9;]*m`)

type TaskProgressSnapshot struct {
	Hosts          int64     `json:"hosts"`
	Templates      int64     `json:"templates"`
	TotalRequests  int64     `json:"total_requests"`
	Requests       int64     `json:"requests"`
	Matched        int64     `json:"matched"`
	Errors         int64     `json:"errors"`
	Percent        float64   `json:"percent"`
	LastUpdatedAt  time.Time `json:"last_updated_at"`
	LastMessage    string    `json:"last_message,omitempty"`
	LastEventSeq   int64     `json:"last_event_seq"`
	Finished       bool      `json:"finished"`
	FinishedStatus string    `json:"finished_status,omitempty"`
}

type TaskLogEvent struct {
	Seq     int64     `json:"seq"`
	Time    time.Time `json:"time"`
	Level   string    `json:"level"`
	Type    string    `json:"type"`
	Message string    `json:"message"`
	Tags    []string  `json:"tags,omitempty"`
}

type TaskLogsPage struct {
	Events     []TaskLogEvent
	NextOffset int64
	HasMore    bool
}

type ResultSummary struct {
	CriticalCount int
	HighCount     int
	MediumCount   int
	LowCount      int
	InfoCount     int
	TechCount     int
	PluginCount   int
	TargetCount   int
	TotalRequests int64
	RealRequests  int64
}

type progressLogState struct {
	lastLoggedAt  time.Time
	lastPercent10 int64
	lastMatched   int64
	lastErrors    int64
}

type cliStatsPayload struct {
	Templates      string `json:"templates"`
	Hosts          string `json:"hosts"`
	Matched        string `json:"matched"`
	Requests       string `json:"requests"`
	ActualRequests string `json:"actual_requests"`
	Total          string `json:"total"`
	Errors         string `json:"errors"`
	Percent        string `json:"percent"`
}

type scannerErrorLogEntry struct {
	Template  string     `json:"template"`
	Type      string     `json:"type"`
	Input     string     `json:"input"`
	Timestamp *time.Time `json:"timestamp"`
	Address   string     `json:"address"`
	Error     string     `json:"error"`
}

type ResultHandler func(payload map[string]interface{})

// State 保存单个扫描任务的运行时状态。
type State struct {
	ID               int64
	TaskNo           string
	TaskName         string
	TargetCount      int
	LogFilePath      string
	MatchLogFilePath string
	ErrorLogFilePath string
	ProgressFilePath string
	LogFile          *os.File
	MatchLogFile     *os.File

	mu                  sync.RWMutex
	events              []TaskLogEvent
	nextSeq             int64
	progress            TaskProgressSnapshot
	resultSummary       ResultSummary
	matchedTemplate     map[string]struct{}
	matchedResults      map[string]struct{}
	lastProgressLog     progressLogState
	lastStats           TaskProgressSnapshot
	completedRequests   int64
	lastLogicalRequests int64
	mirroredErrors      int64
	httpStatsBase       map[string]int
	subscribers         map[chan TaskLogEvent]struct{}
}

func NewState(taskID int64, taskNo, taskName string, targetCount int, runtimeDir string) (*State, error) {
	taskDir := filepath.Join(runtimeDir, fmt.Sprintf("%d", taskID))
	if err := os.MkdirAll(taskDir, 0o755); err != nil {
		return nil, err
	}

	logFilePath := filepath.Join(taskDir, "events.jsonl")
	events, nextSeq := loadExistingEvents(logFilePath, 5000)
	progress := loadProgressSnapshot(filepath.Join(taskDir, "progress.json"))
	matchedResults := make(map[string]struct{})
	logFile, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	matchLogFilePath := filepath.Join(taskDir, "match.log")
	for key := range loadExistingResultMessages(matchLogFilePath) {
		matchedResults[key] = struct{}{}
	}
	if matchedCount := int64(len(matchedResults)); matchedCount > progress.Matched {
		progress.Matched = matchedCount
	}
	matchLogFile, err := os.OpenFile(matchLogFilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		_ = logFile.Close()
		return nil, err
	}

	return &State{
		ID:               taskID,
		TaskNo:           taskNo,
		TaskName:         taskName,
		TargetCount:      targetCount,
		LogFilePath:      logFilePath,
		MatchLogFilePath: matchLogFilePath,
		ErrorLogFilePath: filepath.Join(taskDir, "error.log"),
		ProgressFilePath: filepath.Join(taskDir, "progress.json"),
		LogFile:          logFile,
		MatchLogFile:     matchLogFile,
		matchedTemplate:  make(map[string]struct{}),
		matchedResults:   matchedResults,
		subscribers:      make(map[chan TaskLogEvent]struct{}),
		events:           events,
		nextSeq:          nextSeq,
		httpStatsBase:    loadHTTPStatsBase(events),
		resultSummary: ResultSummary{
			TargetCount: targetCount,
		},
		progress:          progress,
		completedRequests: estimateCompletedRequests(progress),
	}, nil
}

func (s *State) AppendHTTPStats(current map[string]int) {
	if len(current) == 0 {
		return
	}

	s.mu.RLock()
	base := cloneHTTPStatsCounts(s.httpStatsBase)
	s.mu.RUnlock()

	merged := mergeHTTPStatsCounts(base, current)
	s.AppendEvent(TaskLogEvent{
		Time:    time.Now(),
		Level:   "info",
		Type:    "http_stats",
		Message: formatHTTPStatsMessage(merged),
	})
}

func (s *State) Append(level, eventType, message string) {
	s.AppendEvent(TaskLogEvent{
		Time:    time.Now(),
		Level:   level,
		Type:    eventType,
		Message: message,
	})
}

// AppendResult records a match event with normalized template tags.
func (s *State) AppendResult(message string, tags []string) {
	s.AppendEvent(TaskLogEvent{
		Time:    time.Now(),
		Level:   "match",
		Type:    "result",
		Message: message,
		Tags:    NormalizeResultTags(tags),
	})
}

func (s *State) AppendEvent(event TaskLogEvent) {
	if event.Time.IsZero() {
		event.Time = time.Now()
	}

	s.mu.Lock()
	if event.Seq == 0 {
		s.nextSeq++
		event.Seq = s.nextSeq
	}
	if len(s.events) >= 5000 {
		s.events = append(append([]TaskLogEvent{}, s.events[1:]...), event)
	} else {
		s.events = append(s.events, event)
	}
	s.progress.LastEventSeq = event.Seq
	s.progress.LastUpdatedAt = event.Time
	s.progress.LastMessage = event.Message
	if s.LogFile != nil {
		if encoded, err := json.Marshal(event); err == nil {
			writeLogLine(s.LogFile, encoded)
			if strings.EqualFold(event.Level, "match") && s.MatchLogFile != nil {
				writeLogLine(s.MatchLogFile, encoded)
			}
		}
	}
	s.writeProgressSnapshotLocked()

	subscribers := make([]chan TaskLogEvent, 0, len(s.subscribers))
	for ch := range s.subscribers {
		subscribers = append(subscribers, ch)
	}
	s.mu.Unlock()

	for _, ch := range subscribers {
		select {
		case ch <- event:
		default:
		}
	}
}

func (s *State) UpdateProgress(fn func(*TaskProgressSnapshot)) {
	s.mu.Lock()
	fn(&s.progress)
	s.writeProgressSnapshotLocked()
	s.mu.Unlock()
}

func (s *State) SnapshotProgress() TaskProgressSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.progress
}

func (s *State) RecordResult(templateID, templateName, severity string, tags []string, keys ...string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := ""
	if len(keys) > 0 {
		key = strings.TrimSpace(keys[0])
	}
	if key != "" {
		if s.matchedResults == nil {
			s.matchedResults = make(map[string]struct{})
		}
		if _, ok := s.matchedResults[key]; ok {
			return false
		}
		s.matchedResults[key] = struct{}{}
	}

	templateID = strings.TrimSpace(templateID)
	if s.matchedTemplate == nil {
		s.matchedTemplate = make(map[string]struct{})
	}
	if templateID != "" {
		s.matchedTemplate[templateID] = struct{}{}
	}
	if HasTechTag(tags) {
		s.resultSummary.TechCount++
		s.progress.Matched++
		s.writeProgressSnapshotLocked()
		return true
	}

	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		s.resultSummary.CriticalCount++
	case "high":
		s.resultSummary.HighCount++
	case "medium":
		s.resultSummary.MediumCount++
	case "low":
		s.resultSummary.LowCount++
	case "info", "informational":
		s.resultSummary.InfoCount++
	}
	s.progress.Matched++
	s.writeProgressSnapshotLocked()
	return true
}

// HasTechTag reports whether a template tag list contains the tech tag.
func HasTechTag(tags []string) bool {
	for _, tag := range tags {
		for _, item := range strings.Split(tag, ",") {
			if strings.EqualFold(strings.TrimSpace(item), "tech") {
				return true
			}
		}
	}
	return false
}

// NormalizeResultTags trims, lowercases and deduplicates result tags.
func NormalizeResultTags(tags []string) []string {
	result := make([]string, 0, len(tags))
	seen := make(map[string]struct{}, len(tags))
	for _, tag := range tags {
		for _, item := range strings.Split(tag, ",") {
			normalized := strings.ToLower(strings.TrimSpace(item))
			if normalized == "" {
				continue
			}
			if _, ok := seen[normalized]; ok {
				continue
			}
			seen[normalized] = struct{}{}
			result = append(result, normalized)
		}
	}
	sort.Strings(result)
	return result
}

func (s *State) SnapshotResultSummary() ResultSummary {
	s.mu.RLock()
	defer s.mu.RUnlock()

	summary := s.resultSummary
	summary.TargetCount = s.TargetCount
	summary.PluginCount = int(s.progress.Templates)
	summary.TotalRequests = s.progress.TotalRequests
	summary.RealRequests = s.progress.Requests
	return summary
}

func (s *State) SetResultSummary(summary ResultSummary) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.resultSummary = summary
	s.resultSummary.TargetCount = s.TargetCount
	if summary.PluginCount > int(s.progress.Templates) {
		s.progress.Templates = int64(summary.PluginCount)
	}
	if summary.TotalRequests > s.progress.TotalRequests {
		s.progress.TotalRequests = summary.TotalRequests
	}
	if summary.RealRequests > s.progress.Requests {
		s.progress.Requests = summary.RealRequests
	}
	if matched := resultSummaryMatchedCount(summary); matched > s.progress.Matched {
		s.progress.Matched = matched
	}
	if completed := estimateCompletedRequests(s.progress); completed > s.completedRequests {
		s.completedRequests = completed
	}
	s.writeProgressSnapshotLocked()
}

func resultSummaryMatchedCount(summary ResultSummary) int64 {
	return int64(summary.CriticalCount + summary.HighCount + summary.MediumCount + summary.LowCount + summary.InfoCount + summary.TechCount)
}

func estimateCompletedRequests(progress TaskProgressSnapshot) int64 {
	if progress.TotalRequests <= 0 {
		return progress.Requests
	}

	completed := int64(math.Round(progress.Percent / 100 * float64(progress.TotalRequests)))
	if completed < progress.Requests {
		completed = progress.Requests
	}
	if completed > progress.TotalRequests {
		return progress.TotalRequests
	}
	return completed
}

func progressPercentFromCounts(requests, total int64, fallback float64) float64 {
	if total <= 0 {
		return fallback
	}
	if requests <= 0 {
		return 0
	}
	return float64(requests) / float64(total) * 100
}

func (s *State) MarkFinished(status string, finishedAt time.Time, message string) {
	logErrors := s.SyncScannerErrors()

	s.mu.Lock()
	s.progress.Finished = true
	s.progress.FinishedStatus = status
	s.progress.LastUpdatedAt = finishedAt
	s.progress.LastMessage = message
	s.progress.Errors = logErrors
	if status == "success" {
		s.progress.Percent = 100
	}
	s.writeProgressSnapshotLocked()

	subscribers := make([]chan TaskLogEvent, 0, len(s.subscribers))
	for ch := range s.subscribers {
		subscribers = append(subscribers, ch)
		delete(s.subscribers, ch)
	}
	s.mu.Unlock()

	for _, ch := range subscribers {
		close(ch)
	}
}

func (s *State) SyncScannerErrors() int64 {
	s.mu.RLock()
	syncedCount := s.mirroredErrors
	s.mu.RUnlock()

	events, nextCount := ReadScannerErrorEvents(s.ErrorLogFilePath, syncedCount)
	if nextCount == syncedCount {
		return syncedCount
	}

	s.UpdateProgress(func(snapshot *TaskProgressSnapshot) {
		s.mirroredErrors = nextCount
		snapshot.Errors = nextCount
	})

	for _, event := range events {
		s.AppendEvent(event)
	}

	return nextCount
}

func (s *State) ShouldLogProgress(percent float64, matched, errorsCount int64) bool {
	now := time.Now()
	percent10 := int64(percent) / 10

	s.mu.Lock()
	defer s.mu.Unlock()

	logState := &s.lastProgressLog
	shouldLog := logState.lastLoggedAt.IsZero() ||
		percent10 > logState.lastPercent10 ||
		matched != logState.lastMatched ||
		errorsCount != logState.lastErrors ||
		now.Sub(logState.lastLoggedAt) >= 30*time.Second
	if !shouldLog {
		return false
	}

	logState.lastLoggedAt = now
	logState.lastPercent10 = percent10
	logState.lastMatched = matched
	logState.lastErrors = errorsCount
	return true
}

func (s *State) EventsSince(offset int64, limit int) TaskLogsPage {
	s.mu.RLock()
	defer s.mu.RUnlock()

	filtered := make([]TaskLogEvent, 0, limit)
	for _, event := range s.events {
		if event.Seq <= offset {
			continue
		}
		filtered = append(filtered, event)
		if len(filtered) >= limit {
			break
		}
	}

	hasMore := false
	nextOffset := offset
	if len(filtered) > 0 {
		nextOffset = filtered[len(filtered)-1].Seq
	}
	if len(s.events) > 0 && nextOffset < s.events[len(s.events)-1].Seq {
		hasMore = true
	}

	return TaskLogsPage{
		Events:     filtered,
		NextOffset: nextOffset,
		HasMore:    hasMore,
	}
}

func (s *State) EventsBefore(offset int64, limit int) TaskLogsPage {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.events) == 0 || limit <= 0 {
		return TaskLogsPage{}
	}

	end := len(s.events)
	if offset > 0 {
		end = sort.Search(len(s.events), func(i int) bool {
			return s.events[i].Seq >= offset
		})
	}
	if end <= 0 {
		return TaskLogsPage{}
	}

	start := end - limit
	if start < 0 {
		start = 0
	}

	filtered := append([]TaskLogEvent(nil), s.events[start:end]...)
	nextOffset := int64(0)
	if len(filtered) > 0 {
		nextOffset = filtered[0].Seq
	}

	return TaskLogsPage{
		Events:     filtered,
		NextOffset: nextOffset,
		HasMore:    start > 0,
	}
}

func (s *State) FrontendEventsBefore(offset int64, limit int) TaskLogsPage {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return buildFrontendEventsBefore(s.events, offset, limit)
}

func (s *State) Subscribe() (chan TaskLogEvent, func()) {
	ch := make(chan TaskLogEvent, 64)

	s.mu.Lock()
	if len(s.subscribers) >= MaxSubscribers {
		for existing := range s.subscribers {
			delete(s.subscribers, existing)
			close(existing)
			break
		}
	}
	s.subscribers[ch] = struct{}{}
	s.mu.Unlock()

	cancel := func() {
		s.mu.Lock()
		if _, ok := s.subscribers[ch]; ok {
			delete(s.subscribers, ch)
			close(ch)
		}
		s.mu.Unlock()
	}

	return ch, cancel
}

func (s *State) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.LogFile != nil {
		_ = s.LogFile.Close()
		s.LogFile = nil
	}
	if s.MatchLogFile != nil {
		_ = s.MatchLogFile.Close()
		s.MatchLogFile = nil
	}
}

func loadExistingEvents(path string, limit int) ([]TaskLogEvent, int64) {
	file, err := os.Open(path)
	if err != nil {
		return nil, 0
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)

	events := make([]TaskLogEvent, 0, limit)
	var maxSeq int64
	for scanner.Scan() {
		var event TaskLogEvent
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			continue
		}
		if event.Seq > maxSeq {
			maxSeq = event.Seq
		}
		if limit <= 0 {
			continue
		}
		if len(events) < limit {
			events = append(events, event)
			continue
		}
		copy(events, events[1:])
		events[len(events)-1] = event
	}

	return events, maxSeq
}

func loadHTTPStatsBase(events []TaskLogEvent) map[string]int {
	for index := len(events) - 1; index >= 0; index-- {
		event := events[index]
		if !strings.EqualFold(event.Level, "info") || !strings.EqualFold(event.Type, "http_stats") {
			continue
		}
		if counts := parseHTTPStatsMessage(event.Message); len(counts) > 0 {
			return counts
		}
	}
	return nil
}

func loadProgressSnapshot(path string) TaskProgressSnapshot {
	snapshot := TaskProgressSnapshot{
		LastUpdatedAt: time.Now(),
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return snapshot
	}
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return TaskProgressSnapshot{LastUpdatedAt: time.Now()}
	}
	if snapshot.LastUpdatedAt.IsZero() {
		snapshot.LastUpdatedAt = time.Now()
	}
	return snapshot
}

func loadExistingResultMessages(path string) map[string]struct{} {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)

	results := make(map[string]struct{})
	for scanner.Scan() {
		var event TaskLogEvent
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			continue
		}
		if !strings.EqualFold(event.Level, "match") || !strings.EqualFold(event.Type, "result") {
			continue
		}
		key := strings.TrimSpace(event.Message)
		if key == "" {
			continue
		}
		results[key] = struct{}{}
	}
	return results
}

func ReadResultSummaryFromMatchLog(path string, targetCount int) (ResultSummary, bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return ResultSummary{}, false, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)

	summary := ResultSummary{TargetCount: targetCount}
	seenResults := make(map[string]struct{})
	for scanner.Scan() {
		var event TaskLogEvent
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			continue
		}
		key := frontendResultEventKey(event)
		if key == "" {
			continue
		}
		if _, ok := seenResults[key]; ok {
			continue
		}
		seenResults[key] = struct{}{}

		_, severity := parseResultMessageLabels(key)
		if HasTechTag(event.Tags) {
			summary.TechCount++
			continue
		}
		switch strings.ToLower(strings.TrimSpace(severity)) {
		case "critical":
			summary.CriticalCount++
		case "high":
			summary.HighCount++
		case "medium":
			summary.MediumCount++
		case "low":
			summary.LowCount++
		case "info", "informational":
			summary.InfoCount++
		}
	}
	if err := scanner.Err(); err != nil {
		return ResultSummary{}, false, err
	}
	return summary, len(seenResults) > 0, nil
}

func parseResultMessageLabels(message string) (string, string) {
	message = strings.TrimSpace(message)
	if !strings.HasPrefix(message, "[") {
		return "", ""
	}

	labels := make([]string, 0, 3)
	remaining := message
	for strings.HasPrefix(remaining, "[") {
		end := strings.Index(remaining, "]")
		if end <= 0 {
			break
		}
		labels = append(labels, strings.TrimSpace(remaining[1:end]))
		remaining = strings.TrimSpace(remaining[end+1:])
	}
	if len(labels) == 0 {
		return "", ""
	}
	templateName := labels[0]
	severity := ""
	if len(labels) > 1 {
		severity = labels[1]
	}
	return templateName, severity
}

func writeLogLine(file *os.File, encoded []byte) {
	if file == nil {
		return
	}
	_, _ = file.Write(append(encoded, '\n'))
}

func (s *State) writeProgressSnapshotLocked() {
	if s.ProgressFilePath == "" {
		return
	}
	if encoded, err := json.MarshalIndent(s.progress, "", "  "); err == nil {
		_ = os.WriteFile(s.ProgressFilePath, encoded, 0o644)
	}
}

func StreamCommandOutput(reader io.Reader, state *State, stream string, parseResultJSON bool) {
	StreamCommandOutputWithResultHandler(reader, state, stream, parseResultJSON, nil)
}

func StreamCommandOutputWithResultHandler(reader io.Reader, state *State, stream string, parseResultJSON bool, resultHandler ResultHandler) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	httpStatsCapture := false
	httpStatsLines := make([]string, 0, 8)
	trimHTTPStatsHeader := func(message string) string {
		return strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(message, "[INF]"), "[INFO]"))
	}
	trimHTTPStatsDetail := func(message string) string {
		return strings.TrimPrefix(strings.TrimPrefix(message, "[INF]"), "[INFO]")
	}
	flushHTTPStats := func() {
		if len(httpStatsLines) == 0 {
			httpStatsCapture = false
			return
		}
		snapshot := parseHTTPStatsBlock(httpStatsLines)
		state.AppendHTTPStats(snapshot)
		httpStatsLines = httpStatsLines[:0]
		httpStatsCapture = false
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			if httpStatsCapture {
				flushHTTPStats()
			}
			continue
		}

		if parseResultJSON {
			if HandleJSONResultLineWithResultHandler(line, state, resultHandler) {
				continue
			}
		} else {
			if HandleStatsJSONLine(line, state) {
				state.SyncScannerErrors()
				continue
			}
		}

		if level, message, ok := ClassifyScannerLogLine(line); ok {
			if httpStatsCapture {
				if strings.HasPrefix(message, "[INF]   ") || strings.HasPrefix(message, "[INFO]   ") {
					httpStatsLines = append(httpStatsLines, trimHTTPStatsDetail(message))
					continue
				}
				flushHTTPStats()
			}
			if strings.EqualFold(level, "info") && (message == "[INF] Top Status Codes:" || message == "[INFO] Top Status Codes:") {
				httpStatsCapture = true
				httpStatsLines = append(httpStatsLines, trimHTTPStatsHeader(message))
				continue
			}
			if level == "warn" || level == "error" {
				state.Append(level, stream, message)
			}
		}

		if !parseResultJSON {
			state.SyncScannerErrors()
		}
	}

	if httpStatsCapture {
		flushHTTPStats()
	}
	if !parseResultJSON {
		state.SyncScannerErrors()
	}

	if err := scanner.Err(); err != nil {
		state.Append("error", stream+"_scan_error", "读取扫描输出失败")
	}
}

func HandleJSONResultLine(line string, state *State) bool {
	return HandleJSONResultLineWithResultHandler(line, state, nil)
}

func HandleJSONResultLineWithResultHandler(line string, state *State, resultHandler ResultHandler) bool {
	if !strings.HasPrefix(line, "{") {
		return false
	}

	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(line), &payload); err != nil {
		return false
	}

	if IsMatcherStatusFailurePayload(payload) {
		state.Append("info", "match_failure", FormatJSONMatcherFailureMessage(payload))
		return true
	}

	templateID := AsString(payload["template-id"])
	templateName := ""
	severityText := ""
	tags := []string{}
	if infoValue, ok := payload["info"].(map[string]interface{}); ok {
		templateName = AsString(infoValue["name"])
		severityText = AsString(infoValue["severity"])
		tags = ResultTagsFromInfo(infoValue)
	}
	message := FormatJSONResultMessage(payload)
	if !state.RecordResult(FirstNonEmpty(templateID, "unknown-template"), templateName, severityText, tags, message) {
		return true
	}
	state.AppendResult(message, tags)
	if resultHandler != nil {
		resultHandler(payload)
	}
	return true
}

// IsMatcherStatusFailurePayload reports whether a nuclei JSONL event is only a matcher failure status.
func IsMatcherStatusFailurePayload(payload map[string]interface{}) bool {
	rawStatus, ok := payload["matcher-status"]
	if !ok {
		return false
	}

	switch status := rawStatus.(type) {
	case bool:
		return !status
	case string:
		normalized := strings.ToLower(strings.TrimSpace(status))
		return normalized == "false" || normalized == "0" || normalized == "failed"
	case float64:
		return status == 0
	case int:
		return status == 0
	default:
		return false
	}
}

func FormatJSONMatcherFailureMessage(payload map[string]interface{}) string {
	templateID := strings.TrimSpace(AsString(payload["template-id"]))
	templateName := templateID
	severityText := strings.TrimSpace(AsString(payload["severity"]))
	if infoValue, ok := payload["info"].(map[string]interface{}); ok {
		if name := strings.TrimSpace(AsString(infoValue["name"])); name != "" {
			templateName = name
		}
		if severity := strings.TrimSpace(AsString(infoValue["severity"])); severity != "" {
			severityText = severity
		}
	}
	if templateName == "" {
		templateName = "unknown-template"
	}
	if severityText == "" {
		severityText = "unknown"
	}

	labels := []string{templateName, severityText}
	if matcherName := strings.TrimSpace(AsString(payload["matcher-name"])); matcherName != "" {
		labels = append(labels, matcherName)
	} else if extractorName := strings.TrimSpace(AsString(payload["extractor-name"])); extractorName != "" {
		labels = append(labels, extractorName)
	}

	host := FirstNonEmpty(
		AsString(payload["matched-at"]),
		AsString(payload["host"]),
		AsString(payload["url"]),
	)
	if host == "" {
		host = "unknown-target"
	}

	return fmt.Sprintf("[%s] 匹配失败 %s", strings.Join(labels, "]["), host)
}

func FormatJSONResultMessage(payload map[string]interface{}) string {
	templateID := strings.TrimSpace(AsString(payload["template-id"]))
	templateName := templateID
	severityText := strings.TrimSpace(AsString(payload["severity"]))
	if infoValue, ok := payload["info"].(map[string]interface{}); ok {
		if name := strings.TrimSpace(AsString(infoValue["name"])); name != "" {
			templateName = name
		}
		if severity := strings.TrimSpace(AsString(infoValue["severity"])); severity != "" {
			severityText = severity
		}
	}
	if templateName == "" {
		templateName = "unknown-template"
	}
	if severityText == "" {
		severityText = "unknown"
	}

	labels := []string{templateName, severityText}
	if matcherName := strings.TrimSpace(AsString(payload["matcher-name"])); matcherName != "" {
		labels = append(labels, matcherName)
	} else if extractorName := strings.TrimSpace(AsString(payload["extractor-name"])); extractorName != "" {
		labels = append(labels, extractorName)
	}

	host := FirstNonEmpty(
		AsString(payload["matched-at"]),
		AsString(payload["host"]),
		AsString(payload["url"]),
	)
	if host == "" {
		host = "unknown-target"
	}

	message := fmt.Sprintf("[%s] 命中 %s", strings.Join(labels, "]["), host)
	if extractedResults := formatExtractedResultsLine(payload["extracted-results"]); extractedResults != "" {
		message += "\n" + extractedResults
	}
	return message
}

func formatExtractedResultsLine(value interface{}) string {
	var results []string

	switch typed := value.(type) {
	case []interface{}:
		results = make([]string, 0, len(typed))
		for _, item := range typed {
			if normalized := strings.TrimSpace(AsString(item)); normalized != "" {
				results = append(results, normalized)
			}
		}
	case []string:
		results = make([]string, 0, len(typed))
		for _, item := range typed {
			if normalized := strings.TrimSpace(item); normalized != "" {
				results = append(results, normalized)
			}
		}
	default:
		if normalized := strings.TrimSpace(AsString(value)); normalized != "" {
			results = append(results, normalized)
		}
	}

	if len(results) == 0 {
		return ""
	}
	return fmt.Sprintf("extracted-results：%s", strings.Join(results, ", "))
}

// ResultTagsFromInfo extracts normalized tags from a nuclei result info object.
func ResultTagsFromInfo(info map[string]interface{}) []string {
	if len(info) == 0 {
		return nil
	}
	return NormalizeResultTags(resultStringSlice(info["tags"]))
}

func resultStringSlice(value interface{}) []string {
	switch typed := value.(type) {
	case []interface{}:
		result := make([]string, 0, len(typed))
		for _, item := range typed {
			result = append(result, AsString(item))
		}
		return result
	case []string:
		return typed
	default:
		text := AsString(value)
		if text == "" {
			return nil
		}
		return []string{text}
	}
}

func HandleStatsJSONLine(line string, state *State) bool {
	if !strings.HasPrefix(line, "{") {
		return false
	}

	var payload cliStatsPayload
	if err := json.Unmarshal([]byte(line), &payload); err != nil {
		return false
	}
	if payload.Requests == "" && payload.ActualRequests == "" && payload.Total == "" && payload.Matched == "" && payload.Errors == "" {
		return false
	}

	requests := ParseInt64(payload.Requests)
	actualRequests := ParseInt64(payload.ActualRequests)
	if actualRequests == 0 && payload.ActualRequests == "" {
		actualRequests = requests
	}
	total := ParseInt64(payload.Total)
	errorsCount := state.SyncScannerErrors()
	hosts := ParseInt64(payload.Hosts)
	templates := ParseInt64(payload.Templates)
	percent := ParseFloat64(payload.Percent)
	matched := int64(0)

	state.UpdateProgress(func(snapshot *TaskProgressSnapshot) {
		logicalDelta := requests - state.lastLogicalRequests
		if logicalDelta < 0 {
			logicalDelta = requests
		}
		state.completedRequests += logicalDelta

		requestDelta := actualRequests - state.lastStats.Requests
		if requestDelta < 0 {
			requestDelta = actualRequests
		}
		snapshot.Requests += requestDelta
		if total > snapshot.TotalRequests {
			snapshot.TotalRequests = total
		}
		if hosts > snapshot.Hosts {
			snapshot.Hosts = hosts
		}
		if templates > snapshot.Templates {
			snapshot.Templates = templates
		}
		snapshot.Errors = errorsCount
		snapshot.Percent = NormalizeProgressPercent(
			progressPercentFromCounts(state.completedRequests, snapshot.TotalRequests, percent),
			state.completedRequests,
			snapshot.TotalRequests,
		)
		percent = snapshot.Percent
		snapshot.LastUpdatedAt = time.Now()
		snapshot.LastMessage = "扫描进度更新"
		snapshot.FinishedStatus = "running"
		state.lastLogicalRequests = requests
		state.lastStats.Requests = actualRequests
		state.lastStats.TotalRequests = total
		state.lastStats.Errors = errorsCount
		state.lastStats.Hosts = hosts
		state.lastStats.Templates = templates
		state.lastStats.Percent = snapshot.Percent
		matched = snapshot.Matched
	})

	if state.ShouldLogProgress(percent, matched, errorsCount) {
		state.Append("info", "progress", "扫描进度更新")
	}
	return true
}

func FilterFrontendLogEvents(events []TaskLogEvent) []TaskLogEvent {
	if len(events) == 0 {
		return nil
	}

	filtered := make([]TaskLogEvent, 0, len(events))
	seenResults := make(map[string]struct{})
	indexedResults := make(map[string]int)
	matched := 0
	for _, event := range events {
		if ShouldHideFrontendLogEvent(event) {
			continue
		}
		filtered, matched = appendLatestFrontendEvent(filtered, seenResults, indexedResults, matched, len(events), event)
	}
	return filtered
}

func buildFrontendEventsBefore(events []TaskLogEvent, offset int64, limit int) TaskLogsPage {
	if len(events) == 0 || limit <= 0 {
		return TaskLogsPage{}
	}

	filtered := make([]TaskLogEvent, 0, limit)
	matched := 0
	seenResults := make(map[string]struct{})
	indexedResults := make(map[string]int)
	for _, event := range events {
		if offset > 0 && event.Seq >= offset {
			break
		}
		if ShouldHideFrontendLogEvent(event) {
			continue
		}

		filtered, matched = appendLatestFrontendEvent(filtered, seenResults, indexedResults, matched, limit, event)
	}

	nextOffset := int64(0)
	if len(filtered) > 0 {
		nextOffset = filtered[0].Seq
	}

	return TaskLogsPage{
		Events:     filtered,
		NextOffset: nextOffset,
		HasMore:    matched > len(filtered),
	}
}

func frontendResultEventKey(event TaskLogEvent) string {
	if !strings.EqualFold(event.Level, "match") || !strings.EqualFold(event.Type, "result") {
		if strings.EqualFold(event.Level, "info") && strings.EqualFold(event.Type, "http_stats") {
			return "http_stats"
		}
		return ""
	}
	return strings.TrimSpace(event.Message)
}

func appendLatestFrontendEvent(events []TaskLogEvent, seenResults map[string]struct{}, indexedResults map[string]int, matched, limit int, event TaskLogEvent) ([]TaskLogEvent, int) {
	key := frontendResultEventKey(event)
	if key != "" {
		if _, ok := seenResults[key]; !ok {
			seenResults[key] = struct{}{}
			matched++
		}
		if index, ok := indexedResults[key]; ok {
			events = removeIndexedFrontendEvent(events, indexedResults, index)
		}
	} else {
		matched++
	}

	events = append(events, event)
	if key != "" {
		indexedResults[key] = len(events) - 1
	}
	if len(events) > limit {
		events = removeIndexedFrontendEvent(events, indexedResults, 0)
	}
	return events, matched
}

func removeIndexedFrontendEvent(events []TaskLogEvent, indexedResults map[string]int, index int) []TaskLogEvent {
	if index < 0 || index >= len(events) {
		return events
	}

	if key := frontendResultEventKey(events[index]); key != "" {
		delete(indexedResults, key)
	}
	events = append(events[:index], events[index+1:]...)
	for key, itemIndex := range indexedResults {
		if itemIndex > index {
			indexedResults[key] = itemIndex - 1
		}
	}
	return events
}

func ShouldHideFrontendLogEvent(event TaskLogEvent) bool {
	level := strings.TrimSpace(event.Level)
	if strings.EqualFold(level, "warn") || strings.EqualFold(level, "error") {
		return true
	}
	return false
}

func ClassifyScannerLogLine(line string) (string, string, bool) {
	message := strings.TrimSpace(ansiLogPattern.ReplaceAllString(line, ""))
	if message == "" {
		return "", "", false
	}

	upper := strings.ToUpper(message)
	switch {
	case strings.HasPrefix(upper, "[WRN]"), strings.HasPrefix(upper, "[WARN]"):
		return "warn", message, true
	case strings.HasPrefix(upper, "[ERR]"), strings.HasPrefix(upper, "[ERROR]"), strings.HasPrefix(upper, "[FTL]"), strings.HasPrefix(upper, "[FATAL]"):
		return "error", message, true
	case strings.HasPrefix(upper, "[INF]"), strings.HasPrefix(upper, "[INFO]"):
		return "info", message, true
	default:
		return "", "", false
	}
}

func ReadScannerErrorEvents(path string, skip int64) ([]TaskLogEvent, int64) {
	if strings.TrimSpace(path) == "" {
		return nil, skip
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, skip
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)

	events := make([]TaskLogEvent, 0)
	for seen := int64(0); scanner.Scan(); {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		seen++
		if seen <= skip {
			continue
		}

		event, ok := BuildScannerErrorEvent(line)
		if !ok {
			break
		}
		events = append(events, event)
	}

	if err := scanner.Err(); err != nil {
		return events, skip + int64(len(events))
	}

	return events, skip + int64(len(events))
}

func BuildScannerErrorEvent(line string) (TaskLogEvent, bool) {
	var entry scannerErrorLogEntry
	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		return TaskLogEvent{}, false
	}

	eventTime := time.Now()
	if entry.Timestamp != nil && !entry.Timestamp.IsZero() {
		eventTime = *entry.Timestamp
	}

	return TaskLogEvent{
		Time:    eventTime,
		Level:   "error",
		Type:    "scanner_error",
		Message: FormatScannerErrorMessage(entry),
	}, true
}

func FormatScannerErrorMessage(entry scannerErrorLogEntry) string {
	labels := make([]string, 0, 2)
	if template := NormalizeScannerErrorTemplate(entry.Template); template != "" {
		labels = append(labels, template)
	}
	if requestType := strings.TrimSpace(entry.Type); requestType != "" {
		labels = append(labels, requestType)
	}

	label := ""
	if len(labels) > 0 {
		label = "[" + strings.Join(labels, "][") + "] "
	}

	target := FirstNonEmpty(entry.Input, entry.Address)
	errorMessage := strings.TrimSpace(entry.Error)

	switch {
	case target != "" && errorMessage != "":
		return fmt.Sprintf("%s%s: %s", label, target, errorMessage)
	case target != "":
		return label + target
	case errorMessage != "":
		return label + errorMessage
	default:
		return strings.TrimSpace(entry.Template)
	}
}

func NormalizeScannerErrorTemplate(template string) string {
	template = strings.TrimSpace(template)
	if template == "" {
		return ""
	}

	base := filepath.Base(template)
	ext := filepath.Ext(base)
	if strings.EqualFold(ext, ".yaml") {
		base = strings.TrimSuffix(base, ext)
	}
	return base
}

func ReadLogEventsFromFile(path string, offset int64, limit int) ([]TaskLogEvent, bool, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, false, offset, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)

	events := make([]TaskLogEvent, 0, limit)
	hasMore := false
	nextOffset := offset

	for scanner.Scan() {
		var event TaskLogEvent
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			continue
		}
		if event.Seq <= offset {
			continue
		}
		if len(events) < limit {
			events = append(events, event)
			nextOffset = event.Seq
			continue
		}
		hasMore = true
		break
	}
	if err := scanner.Err(); err != nil {
		return nil, false, offset, err
	}

	return events, hasMore, nextOffset, nil
}

func ReadLogEventsBeforeFromFile(path string, offset int64, limit int) ([]TaskLogEvent, bool, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, false, 0, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)

	events := make([]TaskLogEvent, 0, limit)
	matched := 0

	for scanner.Scan() {
		var event TaskLogEvent
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			continue
		}
		if offset > 0 && event.Seq >= offset {
			break
		}

		matched++
		if len(events) < limit {
			events = append(events, event)
			continue
		}

		copy(events, events[1:])
		events[len(events)-1] = event
	}
	if err := scanner.Err(); err != nil {
		return nil, false, 0, err
	}

	nextOffset := int64(0)
	if len(events) > 0 {
		nextOffset = events[0].Seq
	}

	return events, matched > len(events), nextOffset, nil
}

func ReadFrontendLogEventsBeforeFromFile(path string, offset int64, limit int) ([]TaskLogEvent, bool, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, false, 0, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)

	events := make([]TaskLogEvent, 0, limit)
	matched := 0
	seenResults := make(map[string]struct{})
	indexedResults := make(map[string]int)

	for scanner.Scan() {
		var event TaskLogEvent
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			continue
		}
		if offset > 0 && event.Seq >= offset {
			break
		}
		if ShouldHideFrontendLogEvent(event) {
			continue
		}

		events, matched = appendLatestFrontendEvent(events, seenResults, indexedResults, matched, limit, event)
	}
	if err := scanner.Err(); err != nil {
		return nil, false, 0, err
	}

	nextOffset := int64(0)
	if len(events) > 0 {
		nextOffset = events[0].Seq
	}

	return events, matched > len(events), nextOffset, nil
}

func ParseInt64(value string) int64 {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}

	var parsed int64
	_, _ = fmt.Sscan(value, &parsed)
	return parsed
}

func ParseFloat64(value string) float64 {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}

	var parsed float64
	_, _ = fmt.Sscan(value, &parsed)
	return parsed
}

func parseHTTPStatsBlock(lines []string) map[string]int {
	if len(lines) == 0 {
		return nil
	}

	counts := make(map[string]int)
	for _, line := range lines {
		code, value, ok := parseHTTPStatsLine(line)
		if !ok {
			continue
		}
		counts[code] += value
	}
	if len(counts) == 0 {
		return nil
	}
	return counts
}

func parseHTTPStatsMessage(message string) map[string]int {
	message = strings.TrimSpace(message)
	if message == "" {
		return nil
	}
	return parseHTTPStatsBlock(strings.Split(message, "\n"))
}

func parseHTTPStatsLine(line string) (string, int, bool) {
	line = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(line, "[INF]"), "[INFO]"))
	if line == "" || strings.EqualFold(line, "Top Status Codes:") {
		return "", 0, false
	}

	parts := strings.SplitN(line, ":", 2)
	if len(parts) != 2 {
		return "", 0, false
	}

	code := strings.TrimSpace(parts[0])
	if code == "" {
		return "", 0, false
	}

	value := strings.TrimSpace(parts[1])
	if value == "" {
		return "", 0, false
	}

	var parsed int
	if _, err := fmt.Sscan(value, &parsed); err != nil {
		return "", 0, false
	}
	return code, parsed, true
}

func mergeHTTPStatsCounts(base, current map[string]int) map[string]int {
	if len(base) == 0 && len(current) == 0 {
		return nil
	}

	merged := make(map[string]int, len(base)+len(current))
	for code, value := range base {
		merged[code] = value
	}
	for code, value := range current {
		merged[code] += value
	}
	return merged
}

func cloneHTTPStatsCounts(source map[string]int) map[string]int {
	if len(source) == 0 {
		return nil
	}

	cloned := make(map[string]int, len(source))
	for code, value := range source {
		cloned[code] = value
	}
	return cloned
}

func formatHTTPStatsMessage(counts map[string]int) string {
	if len(counts) == 0 {
		return ""
	}

	type httpStatItem struct {
		Key   string
		Value int
	}

	items := make([]httpStatItem, 0, len(counts))
	for code, value := range counts {
		items = append(items, httpStatItem{Key: code, Value: value})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Value == items[j].Value {
			return items[i].Key < items[j].Key
		}
		return items[i].Value > items[j].Value
	})

	var builder strings.Builder
	builder.WriteString("Top Status Codes:")
	for _, item := range items {
		builder.WriteString("\n  ")
		builder.WriteString(item.Key)
		builder.WriteString(": ")
		builder.WriteString(fmt.Sprintf("%d", item.Value))
	}
	return builder.String()
}

func NormalizeProgressPercent(percent float64, requests, total int64) float64 {
	if total <= 0 {
		if requests > 0 {
			return 100
		}
		return ClampProgressPercent(percent)
	}
	if requests >= total {
		return 100
	}
	return ClampProgressPercent(percent)
}

func ClampProgressPercent(percent float64) float64 {
	if percent < 0 {
		return 0
	}
	return math.Min(percent, 100)
}

func AsString(value interface{}) string {
	switch typed := value.(type) {
	case string:
		return typed
	case fmt.Stringer:
		return typed.String()
	case error:
		return typed.Error()
	default:
		if typed == nil {
			return ""
		}
		return fmt.Sprint(typed)
	}
}

func FirstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}
