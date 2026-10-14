package service

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"ManScan/server/internal/model/dto"
	"ManScan/server/internal/model/entity"
	"ManScan/server/internal/pkg/logx"
)

type dashboardRepositoryStub struct {
	counts        []entity.DashboardVulnerabilityCount
	failAt        string
	calls         []string
	emptyRankings bool
}

func (stub *dashboardRepositoryStub) check(ctx context.Context, operation string) error {
	stub.calls = append(stub.calls, operation)
	if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > dashboardQueryTimeout {
		return errors.New("missing query deadline")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if stub.failAt == operation {
		return errors.New("database credentials and SQL must not reach the client")
	}
	return nil
}

func (stub *dashboardRepositoryStub) ListVulnerabilityCounts(ctx context.Context) ([]entity.DashboardVulnerabilityCount, error) {
	return stub.counts, stub.check(ctx, "vulnerabilities")
}

func (stub *dashboardRepositoryStub) CountHighRiskOpenPorts(ctx context.Context) (int64, error) {
	return 7, stub.check(ctx, "high_risk_ports")
}

func (stub *dashboardRepositoryStub) FindHostRiskCounts(ctx context.Context) (entity.DashboardAssetRiskCount, error) {
	return entity.DashboardAssetRiskCount{High: 3, NoRisk: 2}, stub.check(ctx, "host_risks")
}

func (stub *dashboardRepositoryStub) FindDomainRiskCounts(ctx context.Context) (entity.DashboardAssetRiskCount, error) {
	return entity.DashboardAssetRiskCount{Critical: 1, Unknown: 2}, stub.check(ctx, "domain_risks")
}

func (stub *dashboardRepositoryStub) ListTopHostVulnerabilities(ctx context.Context) ([]entity.DashboardHostCount, error) {
	if stub.emptyRankings {
		return nil, stub.check(ctx, "host_vulnerabilities")
	}
	return []entity.DashboardHostCount{{IPAddress: "10.0.0.1", Count: 8}}, stub.check(ctx, "host_vulnerabilities")
}

func (stub *dashboardRepositoryStub) ListTopHostPorts(ctx context.Context) ([]entity.DashboardHostCount, error) {
	if stub.emptyRankings {
		return nil, stub.check(ctx, "host_ports")
	}
	return []entity.DashboardHostCount{{IPAddress: "10.0.0.1", Count: 9}}, stub.check(ctx, "host_ports")
}

func (stub *dashboardRepositoryStub) ListTopDomainFingerprints(ctx context.Context) ([]entity.DashboardFingerprintCount, error) {
	if stub.emptyRankings {
		return nil, stub.check(ctx, "domain_fingerprints")
	}
	return []entity.DashboardFingerprintCount{{Fingerprint: "nginx", Count: 4}}, stub.check(ctx, "domain_fingerprints")
}

func (stub *dashboardRepositoryStub) ListTopHostFingerprints(ctx context.Context) ([]entity.DashboardFingerprintCount, error) {
	if stub.emptyRankings {
		return nil, stub.check(ctx, "host_fingerprints")
	}
	return []entity.DashboardFingerprintCount{{Fingerprint: "ssh", Count: 5}}, stub.check(ctx, "host_fingerprints")
}

func TestDashboardServiceOverview(t *testing.T) {
	t.Parallel()
	stub := &dashboardRepositoryStub{counts: []entity.DashboardVulnerabilityCount{
		{Status: "unreviewed", Severity: "critical", Count: 1}, {Status: "unreviewed", Severity: "high", Count: 2},
		{Status: "unreviewed", Severity: "medium", Count: 3}, {Status: "unreviewed", Severity: "low", Count: 4},
		{Status: "unreviewed", Severity: "info", Count: 5}, {Status: "unreviewed", Severity: "unknown", Count: 6},
		{Status: "confirmed", Severity: "critical", Count: 7}, {Status: "ticketed", Count: 8},
		{Status: "fixed", Count: 9}, {Status: "false_positive", Count: 10}, {Status: "ignored", Count: 11},
	}}
	result, err := NewDashboardService(stub, nil).GetOverview(context.Background())
	want := &dto.DashboardOverviewResponse{
		VulnerabilityStatus:    dto.DashboardVulnerabilityStatusCounts{Total: 66, Unreviewed: 21, Confirmed: 7, Ticketed: 8, Fixed: 9, FalsePositive: 10, Ignored: 11},
		PendingVulnerabilities: dto.DashboardPendingVulnerabilityCounts{Total: 21, Critical: 1, High: 2, Medium: 3, Low: 4},
		HighRiskOpenPorts:      7,
	}
	if err != nil || !reflect.DeepEqual(result, want) {
		t.Fatalf("result = %+v, error = %v, want %+v", result, err, want)
	}
}

func TestDashboardServiceResponses(t *testing.T) {
	t.Parallel()
	dashboard := NewDashboardService(&dashboardRepositoryStub{}, nil)
	risks, err := dashboard.GetAssetRisks(context.Background())
	if err != nil || risks.Hosts.High != 3 || risks.Hosts.NoRisk != 2 || risks.Domains.Critical != 1 || risks.Domains.Unknown != 2 {
		t.Fatalf("risks = %+v, error = %v", risks, err)
	}
	rankings, err := dashboard.GetHostRankings(context.Background())
	if err != nil || len(rankings.TopVulnerabilities) != 1 || rankings.TopVulnerabilities[0].VulnerabilityCount != 8 || rankings.TopVulnerabilities[0].IPAddress != "10.0.0.1" || len(rankings.TopPorts) != 1 || rankings.TopPorts[0].PortCount != 9 {
		t.Fatalf("rankings = %+v, error = %v", rankings, err)
	}
	fingerprints, err := dashboard.GetServiceFingerprints(context.Background())
	if err != nil || len(fingerprints.Hosts) != 1 || fingerprints.Hosts[0].ServiceName != "ssh" || fingerprints.Hosts[0].Count != 5 || len(fingerprints.Domains) != 1 || fingerprints.Domains[0].AppName != "nginx" || fingerprints.Domains[0].Count != 4 {
		t.Fatalf("fingerprints = %+v, error = %v", fingerprints, err)
	}
}

func TestDashboardServiceEmptyRankingsReturnArrays(t *testing.T) {
	t.Parallel()
	dashboard := NewDashboardService(&dashboardRepositoryStub{emptyRankings: true}, nil)
	rankings, err := dashboard.GetHostRankings(context.Background())
	if err != nil || rankings.TopVulnerabilities == nil || len(rankings.TopVulnerabilities) != 0 || rankings.TopPorts == nil || len(rankings.TopPorts) != 0 {
		t.Fatalf("empty rankings = %+v, error = %v", rankings, err)
	}
	fingerprints, err := dashboard.GetServiceFingerprints(context.Background())
	if err != nil || fingerprints.Domains == nil || len(fingerprints.Domains) != 0 || fingerprints.Hosts == nil || len(fingerprints.Hosts) != 0 {
		t.Fatalf("empty fingerprints = %+v, error = %v", fingerprints, err)
	}
}

func TestDashboardServiceQueryErrors(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		first, second string
		query         func(DashboardService, context.Context) error
	}{
		{"vulnerabilities", "high_risk_ports", func(dashboard DashboardService, ctx context.Context) error {
			_, err := dashboard.GetOverview(ctx)
			return err
		}},
		{"host_risks", "domain_risks", func(dashboard DashboardService, ctx context.Context) error {
			_, err := dashboard.GetAssetRisks(ctx)
			return err
		}},
		{"host_vulnerabilities", "host_ports", func(dashboard DashboardService, ctx context.Context) error {
			_, err := dashboard.GetHostRankings(ctx)
			return err
		}},
		{"domain_fingerprints", "host_fingerprints", func(dashboard DashboardService, ctx context.Context) error {
			_, err := dashboard.GetServiceFingerprints(ctx)
			return err
		}},
	} {
		for _, operation := range []string{testCase.first, testCase.second} {
			t.Run(operation, func(t *testing.T) {
				stub := &dashboardRepositoryStub{failAt: operation}
				err := testCase.query(NewDashboardService(stub, nil), context.Background())
				if !errors.Is(err, ErrDashboardUnavailable) {
					t.Fatalf("error = %v, want sanitized business error", err)
				}
				if operation == testCase.first && len(stub.calls) != 1 {
					t.Fatalf("calls = %v, must stop after first error", stub.calls)
				}
			})
		}
	}
}

func TestDashboardServiceHonorsParentDeadline(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if _, err := NewDashboardService(&dashboardRepositoryStub{}, logx.New()).GetOverview(ctx); !errors.Is(err, ErrDashboardUnavailable) {
		t.Fatalf("error = %v, want unavailable on expired parent context", err)
	}
}
