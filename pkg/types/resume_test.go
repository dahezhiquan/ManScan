package types

import "testing"

func TestResumeCfgCompileIncompleteEmptyInFlightRerunsAll(t *testing.T) {
	t.Parallel()

	resumeCfg := NewResumeCfg()
	resumeCfg.ResumeFrom["template-a"] = &ResumeInfo{
		Completed: false,
		InFlight:  map[uint32]struct{}{},
	}

	resumeCfg.Compile()

	resumeInfo := resumeCfg.ResumeFrom["template-a"]
	if resumeInfo.GetSkipUnder() != 0 {
		t.Fatalf("SkipUnder = %d, want 0", resumeInfo.GetSkipUnder())
	}
	if resumeInfo.GetDoAbove() != 0 {
		t.Fatalf("DoAbove = %d, want 0", resumeInfo.GetDoAbove())
	}
	if resumeInfo.IsInFlight(0) {
		t.Fatalf("index 0 should not be marked as repeat-only for an empty checkpoint")
	}
}
