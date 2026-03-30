package route53

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	r53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
)

type mockR53Client struct {
	zones   []r53types.HostedZone
	records map[string][]r53types.ResourceRecordSet
}

func (m *mockR53Client) ListHostedZones(_ context.Context, _ *route53.ListHostedZonesInput, _ ...func(*route53.Options)) (*route53.ListHostedZonesOutput, error) {
	return &route53.ListHostedZonesOutput{
		HostedZones: m.zones,
		IsTruncated: false,
	}, nil
}

func (m *mockR53Client) ListResourceRecordSets(_ context.Context, in *route53.ListResourceRecordSetsInput, _ ...func(*route53.Options)) (*route53.ListResourceRecordSetsOutput, error) {
	rrs := m.records[aws.ToString(in.HostedZoneId)]
	return &route53.ListResourceRecordSetsOutput{
		ResourceRecordSets: rrs,
		IsTruncated:        false,
	}, nil
}

func TestFetchRecords_FiltersCorrectTypes(t *testing.T) {
	client := &mockR53Client{
		zones: []r53types.HostedZone{
			{Id: aws.String("/hostedzone/Z1"), Name: aws.String("example.com.")},
		},
		records: map[string][]r53types.ResourceRecordSet{
			"/hostedzone/Z1": {
				{
					Name: aws.String("web.example.com."),
					Type: r53types.RRTypeA,
					ResourceRecords: []r53types.ResourceRecord{
						{Value: aws.String("1.2.3.4")},
					},
				},
				{
					Name: aws.String("mail.example.com."),
					Type: r53types.RRTypeMx,
					ResourceRecords: []r53types.ResourceRecord{
						{Value: aws.String("10 mail.example.com")},
					},
				},
				{
					Name: aws.String("api.example.com."),
					Type: r53types.RRTypeCname,
					ResourceRecords: []r53types.ResourceRecord{
						{Value: aws.String("web.example.com")},
					},
				},
				{
					Name: aws.String("ipv6.example.com."),
					Type: r53types.RRTypeAaaa,
					ResourceRecords: []r53types.ResourceRecord{
						{Value: aws.String("::1")},
					},
				},
				{
					Name: aws.String("txt.example.com."),
					Type: r53types.RRTypeTxt,
					ResourceRecords: []r53types.ResourceRecord{
						{Value: aws.String("v=spf1 include:example.com")},
					},
				},
			},
		},
	}

	fetcher := NewFetcher(client)
	records, err := fetcher.FetchRecords(context.Background(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(records) != 3 {
		t.Fatalf("expected 3 records (A, CNAME, AAAA), got %d", len(records))
	}

	types := map[string]bool{}
	for _, r := range records {
		types[r.Type] = true
	}
	for _, expected := range []string{"A", "CNAME", "AAAA"} {
		if !types[expected] {
			t.Errorf("expected record type %s not found", expected)
		}
	}
}

func TestFetchRecords_SkipsAliasRecords(t *testing.T) {
	client := &mockR53Client{
		zones: []r53types.HostedZone{
			{Id: aws.String("/hostedzone/Z1"), Name: aws.String("example.com.")},
		},
		records: map[string][]r53types.ResourceRecordSet{
			"/hostedzone/Z1": {
				{
					Name: aws.String("web.example.com."),
					Type: r53types.RRTypeA,
					ResourceRecords: []r53types.ResourceRecord{
						{Value: aws.String("1.2.3.4")},
					},
				},
				{
					Name: aws.String("alb.example.com."),
					Type: r53types.RRTypeA,
					AliasTarget: &r53types.AliasTarget{
						DNSName:      aws.String("alb-1234.us-east-1.elb.amazonaws.com."),
						HostedZoneId: aws.String("Z35SXDOTRQ7X7K"),
					},
				},
			},
		},
	}

	fetcher := NewFetcher(client)
	records, err := fetcher.FetchRecords(context.Background(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(records) != 1 {
		t.Fatalf("expected 1 record (alias should be skipped), got %d", len(records))
	}

	if records[0].Name != "web.example.com" {
		t.Errorf("expected 'web.example.com', got '%s'", records[0].Name)
	}
}

func TestFetchRecords_ZoneFilter(t *testing.T) {
	client := &mockR53Client{
		zones: []r53types.HostedZone{
			{Id: aws.String("/hostedzone/Z1"), Name: aws.String("example.com.")},
			{Id: aws.String("/hostedzone/Z2"), Name: aws.String("other.org.")},
		},
		records: map[string][]r53types.ResourceRecordSet{
			"/hostedzone/Z1": {
				{
					Name: aws.String("web.example.com."),
					Type: r53types.RRTypeA,
					ResourceRecords: []r53types.ResourceRecord{
						{Value: aws.String("1.2.3.4")},
					},
				},
			},
			"/hostedzone/Z2": {
				{
					Name: aws.String("web.other.org."),
					Type: r53types.RRTypeA,
					ResourceRecords: []r53types.ResourceRecord{
						{Value: aws.String("5.6.7.8")},
					},
				},
			},
		},
	}

	fetcher := NewFetcher(client)
	records, err := fetcher.FetchRecords(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(records) != 1 {
		t.Fatalf("expected 1 record (filtered to example.com), got %d", len(records))
	}
	if records[0].HostedZone != "example.com" {
		t.Errorf("expected hosted zone 'example.com', got '%s'", records[0].HostedZone)
	}
}

func TestFetchRecords_SkipsPrivateZones(t *testing.T) {
	client := &mockR53Client{
		zones: []r53types.HostedZone{
			{Id: aws.String("/hostedzone/Z1"), Name: aws.String("example.com."), Config: &r53types.HostedZoneConfig{PrivateZone: true}},
			{Id: aws.String("/hostedzone/Z2"), Name: aws.String("public.com.")},
		},
		records: map[string][]r53types.ResourceRecordSet{
			"/hostedzone/Z1": {
				{
					Name: aws.String("internal.example.com."),
					Type: r53types.RRTypeA,
					ResourceRecords: []r53types.ResourceRecord{
						{Value: aws.String("10.0.0.1")},
					},
				},
			},
			"/hostedzone/Z2": {
				{
					Name: aws.String("web.public.com."),
					Type: r53types.RRTypeA,
					ResourceRecords: []r53types.ResourceRecord{
						{Value: aws.String("1.2.3.4")},
					},
				},
			},
		},
	}

	fetcher := NewFetcher(client)
	records, err := fetcher.FetchRecords(context.Background(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(records) != 1 {
		t.Fatalf("expected 1 record (private zone skipped), got %d", len(records))
	}
	if records[0].Name != "web.public.com" {
		t.Errorf("expected 'web.public.com', got '%s'", records[0].Name)
	}
}

func TestFetchRecords_EmptyZone(t *testing.T) {
	client := &mockR53Client{
		zones: []r53types.HostedZone{
			{Id: aws.String("/hostedzone/Z1"), Name: aws.String("empty.com.")},
		},
		records: map[string][]r53types.ResourceRecordSet{
			"/hostedzone/Z1": {},
		},
	}

	fetcher := NewFetcher(client)
	records, err := fetcher.FetchRecords(context.Background(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(records) != 0 {
		t.Fatalf("expected 0 records, got %d", len(records))
	}
}

func TestFetchRecords_TrailingDotStripped(t *testing.T) {
	client := &mockR53Client{
		zones: []r53types.HostedZone{
			{Id: aws.String("/hostedzone/Z1"), Name: aws.String("example.com.")},
		},
		records: map[string][]r53types.ResourceRecordSet{
			"/hostedzone/Z1": {
				{
					Name: aws.String("web.example.com."),
					Type: r53types.RRTypeA,
					ResourceRecords: []r53types.ResourceRecord{
						{Value: aws.String("1.2.3.4")},
					},
				},
			},
		},
	}

	fetcher := NewFetcher(client)
	records, err := fetcher.FetchRecords(context.Background(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if records[0].Name != "web.example.com" {
		t.Errorf("trailing dot not stripped: got '%s'", records[0].Name)
	}
	if records[0].HostedZone != "example.com" {
		t.Errorf("trailing dot not stripped from zone: got '%s'", records[0].HostedZone)
	}
}
