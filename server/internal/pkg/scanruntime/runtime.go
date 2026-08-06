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
	PluginCount   int
	TargetCount   int
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

// State 保存单个扫描任务的运行时状态。
type State struct {
	ID               int64
	TaskNo           string
	TaskName         string
	TargetCount      int
	LogFilePath      string
	ErrorLogFilePath string
	ProgressFilePath string
	LogFile          *os.File

	mu              sync.RWMutex
	events          []TaskLogEvent
	nextSeq         int64
	progress        TaskProgressSnapshot
	resultSummary   ResultSummary
	matchedTemplate map[string]struct{}
	lastProgressLog progressLogState
	mirroredErrors  int64
	subscribers     map[chan TaskLogEvent]struct{}
}

func NewState(taskID int64, taskNo, taskName string, targetCount int, runtimeDir string) (*State, error) {
	taskDir := filepath.Join(runtimeDir, fmt.Sprintf("%d", taskID))
	if err := os.MkdirAll(taskDir, 0o755); err != nil {
		return nil, err
	}

	logFilePath := filepath.Join(taskDir, "events.jsonl")
	logFile, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}

	return &State{
		ID:               taskID,
		TaskNo:           taskNo,
		TaskName:         taskName,
		TargetCount:      targetCount,
		LogFilePath:      logFilePath,
		ErrorLogFilePath: filepath.Join(taskDir, "error.log"),
		ProgressFilePath: filepath.Join(taskDir, "progress.json"),
		LogFile:          logFile,
		matchedTemplate:  make(map[string]struct{}),
		subscribers:      make(map[chan TaskLogEvent]struct{}),
		resultSummary: ResultSummary{
			TargetCount: targetCount,
		},
		progress: TaskProgressSnapshot{
			LastUpdatedAt: time.Now(),
		},
	}, nil
}

func (s *State) Append(level, eventType, message string) {
	s.AppendEvent(TaskLogEvent{
		Time:    time.Now(),
		Level:   level,
		Type:    eventType,
		Message: message,
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
			_, _ = s.LogFile.Write(append(encoded, '\n'))
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

func (s *State) RecordResult(templateID, severity string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	templateID = strings.TrimSpace(templateID)
	if templateID != "" {
		s.matchedTemplate[templateID] = struct{}{}
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
}

func (s *State) SnapshotResultSummary() ResultSummary {
	s.mu.RLock()
	defer s.mu.RUnlock()

	summary := s.resultSummary
	summary.TargetCount = s.TargetCount
	summary.PluginCount = int(s.progress.Templates)
	return summary
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
		nextOffset = filtered[len(filtered)-1].Seq + 1
	}
	if len(s.events) > 0 && nextOffset <= s.events[len(s.events)-1].Seq {
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
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		if parseResultJSON {
			if HandleJSONResultLine(line, state) {
				continue
			}
		} else {
			if HandleStatsJSONLine(line, state) {
				state.SyncScannerErrors()
				continue
			}
		}

		if level, message, ok := ClassifyScannerLogLine(line); ok {
			if level == "warn" || level == "error" {
				state.Append(level, stream, message)
			}
		}

		if !parseResultJSON {
			state.SyncScannerErrors()
		}
	}

	if !parseResultJSON {
		state.SyncScannerErrors()
	}

	if err := scanner.Err(); err != nil {
		state.Append("error", stream+"_scan_error", "读取扫描输出失败")
	}
}

func HandleJSONResultLine(line string, state *State) bool {
	if !strings.HasPrefix(line, "{") {
		return false
	}

	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(line), &payload); err != nil {
		return false
	}

	templateID := AsString(payload["template-id"])
	host := FirstNonEmpty(
		AsString(payload["matched-at"]),
		AsString(payload["host"]),
		AsString(payload["url"]),
	)
	severityText := ""
	if infoValue, ok := payload["info"].(map[string]interface{}); ok {
		severityText = AsString(infoValue["severity"])
	}
	state.RecordResult(FirstNonEmpty(templateID, "unknown-template"), severityText)
	state.Append("match", "result", fmt.Sprintf("[%s][%s] 命中 %s",
		FirstNonEmpty(templateID, "unknown-template"),
		FirstNonEmpty(severityText, "unknown"),
		host,
	))
	return true
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
	matched := ParseInt64(payload.Matched)
	errorsCount := state.SyncScannerErrors()
	hosts := ParseInt64(payload.Hosts)
	templates := ParseInt64(payload.Templates)
	percent := NormalizeProgressPercent(ParseFloat64(payload.Percent), actualRequests, total)

	state.UpdateProgress(func(snapshot *TaskProgressSnapshot) {
		snapshot.Requests = actualRequests
		snapshot.TotalRequests = total
		snapshot.Matched = matched
		snapshot.Errors = errorsCount
		snapshot.Hosts = hosts
		snapshot.Templates = templates
		snapshot.Percent = percent
		snapshot.LastUpdatedAt = time.Now()
		snapshot.LastMessage = "扫描进度更新"
		snapshot.FinishedStatus = "running"
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
	for _, event := range events {
		if strings.EqualFold(strings.TrimSpace(event.Level), "warn") {
			continue
		}
		filtered = append(filtered, event)
	}
	return filtered
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
			nextOffset = event.Seq + 1
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
