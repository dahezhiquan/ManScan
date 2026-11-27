package service

import (
	"context"
	"testing"
	"time"

	"ManScan/server/internal/repository"
)

func TestNonHTTPFingerprintPreservesServiceEndpoint(t *testing.T) {
	for _, cachedDomain := range []string{"rjy-f3l-vcse.duxiaoman.com", "rjy-f3l-vcse.duxiaoman.com:443"} {
		t.Run(cachedDomain, func(t *testing.T) {
			repo := &assetDomainRepositoryStub{}
			svc := &scanTaskService{assetDomainRepository: repo}
			resolver := newAssetDomainFingerprintTargetResolver([]assetDomainFingerprintTarget{{
				Input: "rjy-f3l-vcse.duxiaoman.com", Domain: cachedDomain,
			}})
			const endpoint = "rjy-f3l-vcse.duxiaoman.com:5060"
			observations, err := svc.buildAssetDomainServiceAssetsFromPayloadWithResolver(context.Background(), map[string]interface{}{
				"template-id": "sip-options-detect", "type": "javascript",
				"matched-at": endpoint, "input": "rjy-f3l-vcse.duxiaoman.com",
				"host": "rjy-f3l-vcse.duxiaoman.com", "port": "443",
				"matcher-name": "sip",
				"info":         map[string]interface{}{"tags": []string{"detect", "sip", "tcp", "udp"}},
			}, resolver)
			if err != nil || len(observations) != 1 {
				t.Fatalf("fingerprint = %+v, error = %v", observations, err)
			}
			if observations[0].Domain != endpoint || !observations[0].NonHTTPService {
				t.Fatalf("fingerprint = %+v, want actual SIP endpoint", observations[0])
			}
			if err := svc.syncAssetServiceAssets(context.Background(), observations, nil, nil, nil, time.Now()); err != nil {
				t.Fatal(err)
			}
			if len(repo.missingDomainObservations) != 1 || len(repo.missingDomainObservations[0]) != 1 {
				t.Fatalf("missing parents = %+v", repo.missingDomainObservations)
			}
			parent := repo.missingDomainObservations[0][0]
			if parent.Domain != endpoint || parent.Title != "非 HTTP 服务" || parent.HTTPStatusCode != 0 || parent.Response != "" {
				t.Fatalf("parent = %+v", parent)
			}
			if repo.syncServiceAssetObservations[0][0].Domain != parent.Domain {
				t.Fatal("parent and component endpoints differ")
			}
		})
	}
}

func TestNonHTTPFingerprintParentBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name, endpoint, protocol string
		tags                     []string
		wantParent               bool
	}{
		{"network", "redis.example.com:6379", "network", []string{"detect", "redis"}, true},
		{"http", "https://web.example.com:8443/", "http", []string{"tech", "nginx"}, false},
		{"http bare endpoint", "web.example.com:8443", "http", []string{"tech", "nginx"}, false},
		{"javascript http", "https://web.example.com/", "javascript", []string{"detect", "nginx"}, false},
		{"ip service", "192.0.2.1:6379", "network", []string{"detect", "redis"}, false},
		{"ipv6 service", "[2001:db8::1]:6379", "network", []string{"detect", "redis"}, false},
		{"missing port", "redis.example.com", "network", []string{"detect", "redis"}, false},
		{"invalid port", "redis.example.com:65536", "network", []string{"detect", "redis"}, false},
		{"dns vulnerability", "dns.example.com", "dns", []string{"takeover"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := &assetDomainRepositoryStub{}
			svc := &scanTaskService{assetDomainRepository: repo}
			observations, err := svc.buildAssetDomainServiceAssetsFromPayload(context.Background(), map[string]interface{}{
				"template-id": "service-detect", "type": tc.protocol, "matched-at": tc.endpoint,
				"matcher-name": "service", "info": map[string]interface{}{"tags": tc.tags},
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := svc.syncAssetServiceAssets(context.Background(), observations, nil, nil, nil, time.Now()); err != nil {
				t.Fatal(err)
			}
			var parents []repository.AssetDomainObservation
			for _, batch := range repo.missingDomainObservations {
				parents = append(parents, batch...)
			}
			if (len(parents) > 0) != tc.wantParent {
				t.Fatalf("parents = %+v, wantParent = %v", parents, tc.wantParent)
			}
		})
	}
}
