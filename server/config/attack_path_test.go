package config

import "testing"

func TestAttackPathConfiguration(t *testing.T) {
	cfg := AIConfig{}
	if err := cfg.ValidateAttackPath(); err != nil || cfg.AttackPathMode != "hybrid" || cfg.AttackPathConcurrency != 5 || cfg.AttackPathBatchSize != 500 {
		t.Fatalf("invalid defaults: %+v %v", cfg, err)
	}
	for _, bad := range []AIConfig{
		{AttackPathMode: "invalid"}, {AttackPathConcurrency: -1}, {AttackPathConcurrency: 33},
		{AttackPathBatchSize: -1}, {AttackPathBatchSize: 1001},
	} {
		if err := bad.ValidateAttackPath(); err == nil {
			t.Fatalf("accepted invalid configuration: %+v", bad)
		}
	}
	cfg = AIConfig{AttackPathMode: "cli", AttackPathConcurrency: 32, AttackPathBatchSize: 1000}
	if err := cfg.ValidateAttackPath(); err != nil {
		t.Fatal(err)
	}
}
