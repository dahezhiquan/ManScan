package config

import (
	"fmt"
	"strings"
)

// ValidateAttackPath applies bounded defaults for model batch processing.
func (c *AIConfig) ValidateAttackPath() error {
	c.AttackPathMode = strings.TrimSpace(c.AttackPathMode)
	if c.AttackPathMode == "" {
		c.AttackPathMode = "hybrid"
	}
	if c.AttackPathMode != "hybrid" && c.AttackPathMode != "batch" && c.AttackPathMode != "cli" {
		return fmt.Errorf("ai.attack_path_mode 必须为 hybrid、batch 或 cli")
	}
	if c.AttackPathConcurrency == 0 {
		c.AttackPathConcurrency = 5
	}
	if c.AttackPathBatchSize == 0 {
		c.AttackPathBatchSize = 500
	}
	if c.AttackPathConcurrency < 1 || c.AttackPathConcurrency > 32 {
		return fmt.Errorf("ai.attack_path_concurrency 必须在 1 到 32 之间")
	}
	if c.AttackPathBatchSize < 1 || c.AttackPathBatchSize > 1000 {
		return fmt.Errorf("ai.attack_path_batch_size 必须在 1 到 1000 之间")
	}
	return nil
}
