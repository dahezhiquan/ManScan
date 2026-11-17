package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"sync"

	"ManScan/server/internal/repository"
)

// Bump when classifier semantics or pinned local detection dependencies change.
// Prompt text, model, endpoint, CRS directives and wire protocol are also hashed.
const attackPathModelCachePolicy = "v1:coraza-3.8.1:crs-4.25.0:local-evidence-v1"

type attackPathCacheFlight struct {
	done      chan struct{}
	malicious bool
	err       error
}

type cachedAttackPathClassifier struct {
	classifier AttackPathBatchClassifier
	cache      repository.AttackPathModelCacheRepository
	scope      string
	mu         sync.Mutex
	inflight   map[string]*attackPathCacheFlight
}

// NewCachedAttackPathClassifier reuses exact-path model decisions across tasks.
func NewCachedAttackPathClassifier(classifier AttackPathBatchClassifier, cache repository.AttackPathModelCacheRepository, provider, model string) AttackPathBatchClassifier {
	return &cachedAttackPathClassifier{
		classifier: classifier, cache: cache,
		scope:    hashAttackPathCacheParts(attackPathModelCachePolicy, provider, model, attackPathCRSDirectives, aiForceAttackPathProtocol),
		inflight: make(map[string]*attackPathCacheFlight),
	}
}

func hashAttackPathCacheParts(parts ...string) string {
	var framed string
	for _, part := range parts {
		framed += strconv.Itoa(len(part)) + ":" + part
	}
	sum := sha256.Sum256([]byte(framed))
	return hex.EncodeToString(sum[:])
}

func (c *cachedAttackPathClassifier) Classify(ctx context.Context, system string, paths []string) ([]int, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(paths) == 0 || len(paths) > 1000 {
		return nil, errors.New("invalid classification batch size")
	}
	namespace := hashAttackPathCacheParts(c.scope, system)
	keys := make([]string, len(paths))
	unique := make([]string, 0, len(paths))
	pathByKey := make(map[string]string, len(paths))
	for i, path := range paths {
		key := hashAttackPathCacheParts(namespace, path)
		keys[i] = key
		if _, exists := pathByKey[key]; !exists {
			unique = append(unique, key)
			pathByKey[key] = path
		}
	}
	// Lookup and ownership claims are atomic within this service instance. The
	// lock covers short indexed reads, never a model request or waiting on one.
	c.mu.Lock()
	decisions, err := c.cache.FindByKeys(ctx, unique)
	if err != nil {
		c.mu.Unlock()
		return nil, fmt.Errorf("读取攻击路径模型缓存失败: %w", err)
	}
	flights := make(map[string]*attackPathCacheFlight)
	ownedKeys, ownedPaths := make([]string, 0), make([]string, 0)
	for _, key := range unique {
		if _, hit := decisions[key]; hit {
			continue
		}
		flight, exists := c.inflight[key]
		if !exists {
			flight = &attackPathCacheFlight{done: make(chan struct{})}
			c.inflight[key] = flight
			ownedKeys = append(ownedKeys, key)
			ownedPaths = append(ownedPaths, pathByKey[key])
		}
		flights[key] = flight
	}
	c.mu.Unlock()

	if len(ownedPaths) > 0 {
		result, classifyErr := c.classifyMissing(ctx, system, ownedKeys, ownedPaths)
		c.mu.Lock()
		for _, key := range ownedKeys {
			flight := flights[key]
			flight.malicious, flight.err = result[key], classifyErr
			delete(c.inflight, key)
			close(flight.done)
		}
		c.mu.Unlock()
		if classifyErr != nil {
			return nil, classifyErr
		}
	}
	// Submit this call's owned work before waiting; overlapping batches cannot
	// form a wait cycle and independent batches retain upstream concurrency.
	for key, flight := range flights {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-flight.done:
			if flight.err != nil {
				return nil, flight.err
			}
			decisions[key] = flight.malicious
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	indexes := make([]int, 0)
	for i, key := range keys {
		if decisions[key] {
			indexes = append(indexes, i)
		}
	}
	return indexes, nil
}

func (c *cachedAttackPathClassifier) classifyMissing(ctx context.Context, system string, keys, paths []string) (map[string]bool, error) {
	indexes, err := c.classifier.Classify(ctx, system, paths)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if indexes == nil {
		return nil, errors.New("模型未返回完整的攻击路径判定结果")
	}
	if err := validateAttackPathIndexes(indexes, len(paths)); err != nil {
		return nil, err
	}
	decisions := make(map[string]bool, len(keys))
	for _, key := range keys {
		decisions[key] = false
	}
	for _, index := range indexes {
		decisions[keys[index]] = true
	}
	if err := c.cache.Save(ctx, decisions); err != nil {
		return nil, fmt.Errorf("保存攻击路径模型缓存失败: %w", err)
	}
	return decisions, nil
}
