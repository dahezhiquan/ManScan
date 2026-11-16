package service

import (
	"strconv"

	"ManScan/server/config"
)

const (
	attackPathSystemPromptID = "attack_path_filter.system"
	attackPathTaskPromptID   = "attack_path_filter.task"
	attackPathReadPromptID   = "attack_path_filter.tools.read_paths"
	attackPathWritePromptID  = "attack_path_filter.tools.write_filtered_paths"
	attackPathFinishPromptID = "attack_path_filter.tools.finish"
)

type attackPathPrompts struct {
	system, task, readPaths, writeFilteredPaths, finish string
}

func loadAttackPathPrompts(path string, total int) (attackPathPrompts, error) {
	catalog, err := config.LoadPromptCatalog(path)
	if err != nil {
		return attackPathPrompts{}, err
	}
	variables := map[string]string{
		"total":          strconv.Itoa(total),
		"read_default":   strconv.Itoa(attackPathToolDefaultLines),
		"read_max":       strconv.Itoa(attackPathToolMaxLines),
		"read_max_bytes": strconv.Itoa(attackPathToolMaxBytes),
	}
	var prompts attackPathPrompts
	for _, item := range []struct {
		id     string
		target *string
	}{
		{attackPathSystemPromptID, &prompts.system},
		{attackPathTaskPromptID, &prompts.task},
		{attackPathReadPromptID, &prompts.readPaths},
		{attackPathWritePromptID, &prompts.writeFilteredPaths},
		{attackPathFinishPromptID, &prompts.finish},
	} {
		value, err := catalog.Render(item.id, variables)
		if err != nil {
			return attackPathPrompts{}, err
		}
		*item.target = value
	}
	return prompts, nil
}
