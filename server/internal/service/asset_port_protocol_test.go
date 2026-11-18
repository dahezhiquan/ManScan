package service

import (
	"context"
	"fmt"
	"testing"

	"ManScan/server/internal/repository"
)

func TestAssetPortProtocolServiceFallback(t *testing.T) {
	t.Parallel()

	for _, service := range []string{"jdwp", "mssql", "openssh", "rsync"} {
		for _, port := range []uint{1433, 45001} {
			t.Run(fmt.Sprintf("%s/%d", service, port), func(t *testing.T) {
				t.Parallel()
				svc := &scanTaskService{}
				observations, err := svc.buildAssetDomainServiceAssetsFromPayload(context.Background(), map[string]interface{}{
					"template-id": service + "-detect",
					"type":        "javascript",
					"matched-at":  fmt.Sprintf("192.0.2.10:%d", port),
					"info": map[string]interface{}{
						"tags": []string{"js", "network", service, "detect"},
					},
				})
				if err != nil {
					t.Fatal(err)
				}
				if len(observations) != 1 || observations[0].PortProtocol != "tcp" {
					t.Fatalf("observations = %+v, want one TCP service", observations)
				}
				_, ports := splitAssetServiceAssetObservations(context.Background(), observations, nil, nil)
				if len(ports) != 1 || ports[0].PortProtocol != "tcp" || ports[0].ServiceName != service || ports[0].PortNumber != port {
					t.Fatalf("ports = %+v, want %s over TCP on %d", ports, service, port)
				}
			})
		}
	}
}

func TestAssetPortProtocolEvidencePriority(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name      string
		component string
		payload   map[string]interface{}
		tags      []string
		want      string
	}{
		{name: "normalized service", component: " OpenSSH ", want: "tcp"},
		{name: "browser UDP tag", component: "mssql", tags: []string{"network", "udp"}, want: "udp"},
		{name: "explicit transport", component: "mssql", payload: map[string]interface{}{"transport": " UDP "}, want: "udp"},
		{name: "nested metadata", component: "sip", payload: map[string]interface{}{"info": map[string]interface{}{"metadata": map[string]interface{}{"transport": "udp"}}}, want: "udp"},
		{name: "TLS payload metadata", component: "gowvp", payload: map[string]interface{}{"metadata": map[string]interface{}{"transport": "tls"}}, tags: []string{"tcp", "udp"}, want: "tcp"},
		{name: "SSL normalization", component: "sip", payload: map[string]interface{}{"port_protocol": " SSL "}, want: "tcp"},
		{name: "conflicting tags", component: "mssql", tags: []string{"tcp", "udp"}},
		{name: "unknown service", component: "custom-service"},
		{name: "SIP requires transport", component: "sip"},
		{name: "GoWVP requires transport", component: "gowvp"},
		{name: "Mediant requires transport", component: "audiocodes-mediant"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := assetDomainFingerprintPortProtocol(tc.payload, nil, tc.tags, "192.0.2.10:5060", "192.0.2.10:5060", tc.component)
			if got != tc.want {
				t.Fatalf("protocol = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestAssetPortProtocolSIPResponse(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name       string
		templateID string
		response   interface{}
		metadata   map[string]interface{}
		want       string
	}{
		{name: "TCP response", response: `{"service":"sip","transport":"tcp"}`, want: "tcp"},
		{name: "UDP response", response: `{"service":"sip","transport":"udp"}`, want: "udp"},
		{name: "TLS response", response: `{"service":"sip","transport":"tls"}`, want: "tcp"},
		{name: "decoded response", response: map[string]interface{}{"service": "sip", "transport": "udp"}, want: "udp"},
		{name: "metadata without response", metadata: map[string]interface{}{"transport": "udp"}, want: "udp"},
		{name: "metadata wins", metadata: map[string]interface{}{"transport": "tcp"}, response: `{"service":"sip","transport":"udp"}`, want: "tcp"},
		{name: "missing response"},
		{name: "malformed JSON", response: `{"service":"sip","transport":"tcp"`},
		{name: "unsupported transport", response: `{"service":"sip","transport":"quic"}`},
		{name: "missing service", response: `{"transport":"tcp"}`},
		{name: "other service", response: `{"service":"http","transport":"tcp"}`},
		{name: "array is not evidence", response: `[{"service":"sip","transport":"tcp"}]`},
		{name: "nested field is not evidence", response: `{"body":{"service":"sip","transport":"tcp"}}`},
		{name: "unrelated template response", templateID: "custom-detect", response: `{"service":"sip","transport":"tcp"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			templateID := tc.templateID
			if templateID == "" {
				templateID = "sip-options-detect"
			}
			payload := map[string]interface{}{"template-id": templateID, "type": "javascript", "response": tc.response, "metadata": tc.metadata}
			for _, component := range []string{"sip", "gowvp", "audiocodes-mediant"} {
				got := assetDomainFingerprintPortProtocol(payload, nil, []string{"network", "sip", "tcp", "udp"}, "192.0.2.10:5060", "192.0.2.10:5060", component)
				if got != tc.want {
					t.Fatalf("%s protocol = %q, want %q", component, got, tc.want)
				}
			}
		})
	}
}

func TestAssetPortProtocolSIPQueuePreservesBothTransports(t *testing.T) {
	t.Parallel()

	for _, product := range []string{"gowvp", "audiocodes-mediant"} {
		t.Run(product, func(t *testing.T) {
			t.Parallel()
			repo := &assetHostPortRepositoryStub{}
			svc := &scanTaskService{assetDomainRepository: &assetDomainRepositoryStub{}, assetHostPortRepository: repo}
			queue := newAssetDomainServiceAssetQueue(svc)
			for _, transport := range []string{"tcp", "udp", "tls"} {
				queue.Enqueue(assetDomainServiceAssetResultEvent{payload: map[string]interface{}{
					"template-id":       "sip-options-detect",
					"type":              "javascript",
					"matched-at":        "192.0.2.10:45060",
					"response":          fmt.Sprintf(`{"service":"sip","transport":%q}`, transport),
					"extracted-results": []string{product + ":1.2.3"},
					"info": map[string]interface{}{
						"tags": []string{"network", "sip", "voip", "detect", "tcp", "udp", "discovery", "js"},
					},
				}})
			}
			queue.Enqueue(assetDomainServiceAssetResultEvent{completedTarget: "192.0.2.10:45060"})
			queue.CloseAndWait()
			want := map[string]bool{"sip/tcp": true, "sip/udp": true, product + "/tcp": true, product + "/udp": true}
			checkPorts := func(ports []repository.AssetHostPortObservation) {
				t.Helper()
				if len(ports) != len(want) {
					t.Fatalf("ports = %+v, want four protocol/service pairs", ports)
				}
				seen := make(map[string]bool)
				for _, port := range ports {
					key := port.ServiceName + "/" + port.PortProtocol
					if !want[key] || seen[key] || port.PortNumber != 45060 || (port.ServiceName == product && port.AppVersion != "1.2.3") {
						t.Fatalf("unexpected port = %+v", port)
					}
					seen[key] = true
				}
			}
			var persisted []repository.AssetHostPortObservation
			for _, batch := range repo.observationValues {
				persisted = append(persisted, batch...)
			}
			checkPorts(uniqueAssetHostPortObservations(persisted))
			if len(repo.staleObserved) != 1 {
				t.Fatalf("stale syncs = %d, want one", len(repo.staleObserved))
			}
			checkPorts(repo.staleObserved[0])
			cache := assetDomainFingerprintCacheComponents(queue.Observations())
			cache = uniqueAssetDomainFingerprintCacheComponents(append(cache, cache...))
			if len(cache) != len(want) {
				t.Fatalf("cache = %+v, want four protocol/service pairs", cache)
			}
			for _, component := range cache {
				key := component.AppName + "/" + component.PortProtocol
				if !want[key] {
					t.Fatalf("unexpected cached component = %+v", component)
				}
				delete(want, key)
			}
			if len(want) != 0 {
				t.Fatalf("missing cached components = %+v", want)
			}
		})
	}
}
