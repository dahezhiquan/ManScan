package service

import (
	"testing"

	"ManScan/server/internal/model/entity"
)

func TestToAssetDomainListItemIncludesRequestAndResponse(t *testing.T) {
	request := "GET / HTTP/1.1\r\nHost: app.example.com\r\n\r\n"
	response := "HTTP/1.1 200 OK\r\n\r\nok"

	item := toAssetDomainListItem(entity.AssetDomain{
		ID:       1,
		Domain:   "app.example.com:443",
		Request:  &request,
		Response: &response,
	})

	if item.Request != request {
		t.Fatalf("Request = %q, want %q", item.Request, request)
	}
	if item.Response != response {
		t.Fatalf("Response = %q, want %q", item.Response, response)
	}
}
