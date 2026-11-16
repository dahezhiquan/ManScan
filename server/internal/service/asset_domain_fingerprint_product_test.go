package service

import (
	"context"
	"reflect"
	"testing"

	"ManScan/server/internal/model/dto"
)

func TestAssetDomainFingerprintProductVersionAttribution(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name            string
		metadata        map[string]interface{}
		templateProduct string
		extracted       []string
		matcher         string
		want            map[string]string
	}{
		{
			name:      "event metadata assigns only product",
			metadata:  map[string]interface{}{"product": "zookeeper"},
			extracted: []string{"3.6.0"},
			want:      map[string]string{"apache": "", "zookeeper": "3.6.0"},
		},
		{
			name:            "repository metadata fallback",
			templateProduct: "zookeeper", extracted: []string{"3.6.0"},
			want: map[string]string{"apache": "", "zookeeper": "3.6.0"},
		},
		{
			name:     "empty event product falls back to repository",
			metadata: map[string]interface{}{"product": " "}, templateProduct: "zookeeper",
			extracted: []string{"3.6.0"},
			want:      map[string]string{"apache": "", "zookeeper": "3.6.0"},
		},
		{
			name:     "event product takes precedence over repository",
			metadata: map[string]interface{}{"product": " ZooKeeper "}, templateProduct: "apache",
			extracted: []string{"3.6.0"},
			want:      map[string]string{"apache": "", "zookeeper": "3.6.0"},
		},
		{
			name:            "repository product is normalized",
			templateProduct: " ZooKeeper ", extracted: []string{"3.6.0"},
			want: map[string]string{"apache": "", "zookeeper": "3.6.0"},
		},
		{
			name:            "generic version field",
			templateProduct: "zookeeper", extracted: []string{"version:3.6.0"},
			want: map[string]string{"apache": "", "zookeeper": "3.6.0"},
		},
		{
			name:            "quoted JSON version field",
			templateProduct: "zookeeper", extracted: []string{`"version":"3.6.0"`},
			want: map[string]string{"apache": "", "zookeeper": "3.6.0"},
		},
		{
			name:            "normalizable banner",
			templateProduct: "zookeeper", extracted: []string{"ZooKeeper/3.6.0"},
			want: map[string]string{"apache": "", "zookeeper": "3.6.0"},
		},
		{
			name:      "missing product leaves ambiguous versions empty",
			extracted: []string{"3.6.0"},
			want:      map[string]string{"apache": "", "zookeeper": ""},
		},
		{
			name:            "unmatched product does not create components or infer aliases",
			templateProduct: "apache_zookeeper", extracted: []string{"3.6.0"},
			want: map[string]string{"apache": "", "zookeeper": ""},
		},
		{
			name:     "unmatched event product does not fall back to different product",
			metadata: map[string]interface{}{"product": "other"}, templateProduct: "zookeeper",
			extracted: []string{"3.6.0"},
			want:      map[string]string{"apache": "", "zookeeper": ""},
		},
		{
			name:     "product arrays are not coerced to a scalar",
			metadata: map[string]interface{}{"product": []string{"zookeeper", "apache"}}, templateProduct: "zookeeper",
			extracted: []string{"3.6.0"},
			want:      map[string]string{"apache": "", "zookeeper": ""},
		},
		{
			name:     "null product is invalid",
			metadata: map[string]interface{}{"product": nil}, templateProduct: "zookeeper",
			extracted: []string{"3.6.0"},
			want:      map[string]string{"apache": "", "zookeeper": ""},
		},
		{
			name:            "multiple product string is not split",
			templateProduct: "zookeeper,apache", extracted: []string{"3.6.0"},
			want: map[string]string{"apache": "", "zookeeper": ""},
		},
		{
			name:            "non-version text is not assigned",
			templateProduct: "zookeeper", extracted: []string{"ZooKeeper", "3.6.0--build"},
			want: map[string]string{"apache": "", "zookeeper": ""},
		},
		{
			name:            "empty extraction is not assigned",
			templateProduct: "zookeeper",
			want:            map[string]string{"apache": "", "zookeeper": ""},
		},
		{
			name:            "explicit version wins before bare version",
			templateProduct: "zookeeper", extracted: []string{"zookeeper:3.7.0", "3.6.0"},
			want: map[string]string{"apache": "", "zookeeper": "3.7.0"},
		},
		{
			name:            "explicit version wins after generic version",
			templateProduct: "zookeeper", extracted: []string{"version:3.6.0", "zookeeper:3.7.0"},
			want: map[string]string{"apache": "", "zookeeper": "3.7.0"},
		},
		{
			name:            "explicit other component is preserved",
			templateProduct: "zookeeper", extracted: []string{"apache:2.4.57", "3.6.0"},
			want: map[string]string{"apache": "2.4.57", "zookeeper": "3.6.0"},
		},
		{
			name:      "explicit output works without product",
			extracted: []string{"zookeeper:3.6.0"},
			want:      map[string]string{"apache": "", "zookeeper": "3.6.0"},
		},
		{
			name:            "duplicate equivalent versions remain unambiguous",
			templateProduct: "zookeeper", extracted: []string{"3.6.0", "version:3.6.0", "ZooKeeper/3.6.0"},
			want: map[string]string{"apache": "", "zookeeper": "3.6.0"},
		},
		{
			name:            "conflicting bare versions remain unassigned",
			templateProduct: "zookeeper", extracted: []string{"3.6.0", "version:3.7.0", "3.6.0"},
			want: map[string]string{"apache": "", "zookeeper": ""},
		},
		{
			name:            "conflicting inferred versions cannot erase explicit version",
			templateProduct: "zookeeper", extracted: []string{"3.6.0", "zookeeper:3.8.0", "3.7.0"},
			want: map[string]string{"apache": "", "zookeeper": "3.8.0"},
		},
		{
			name:            "matcher component does not receive product version",
			templateProduct: "zookeeper", matcher: "service-banner", extracted: []string{"3.6.0"},
			want: map[string]string{"apache": "", "zookeeper": "3.6.0", "service-banner": ""},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			svc := &scanTaskService{templateRepository: &templateRepositoryStub{
				details: map[string]*dto.TemplateDetail{
					"zookeeper-detect": {
						ID: "zookeeper-detect", Product: tc.templateProduct,
						Tags: []string{"detect", "zookeeper", "apache", "tcp"},
					},
				},
			}}
			for _, endpoint := range []string{"192.0.2.10:2181", "zk.example.test:2181"} {
				payload := map[string]interface{}{
					"template-id": "zookeeper-detect", "matched-at": endpoint, "type": "tcp",
					"matcher-name": tc.matcher, "extracted-results": tc.extracted,
					"info": map[string]interface{}{
						"name": "Apache ZooKeeper 服务识别", "metadata": tc.metadata,
					},
				}
				observations, err := svc.buildAssetDomainServiceAssetsFromPayload(context.Background(), payload)
				if err != nil {
					t.Fatal(err)
				}
				got := make(map[string]string, len(observations))
				for _, observation := range observations {
					got[observation.AppName] = observation.AppVersion
				}
				if !reflect.DeepEqual(got, tc.want) {
					t.Fatalf("%s: component versions = %#v, want %#v", endpoint, got, tc.want)
				}
				if endpoint == "192.0.2.10:2181" {
					_, ports := splitAssetServiceAssetObservations(context.Background(), observations, nil, nil)
					gotPorts := make(map[string]string, len(ports))
					for _, port := range ports {
						gotPorts[port.ServiceName] = port.AppVersion
					}
					if !reflect.DeepEqual(gotPorts, tc.want) {
						t.Fatalf("host-port versions = %#v, want %#v", gotPorts, tc.want)
					}
				}
			}
		})
	}
}
