package templates

// EstimatedRequestsForTarget adjusts network request counts for the target's effective endpoints.
func (template *Template) EstimatedRequestsForTarget(input string) int {
	if template == nil {
		return 0
	}
	count := template.TotalRequests
	if template.SelfContained || template.Flow != "" {
		return count
	}
	for _, request := range template.RequestsNetwork {
		if request != nil {
			count += request.EstimatedRequestsForTarget(input) - request.Requests()
		}
	}
	if count < 0 {
		return 0
	}
	return count
}
