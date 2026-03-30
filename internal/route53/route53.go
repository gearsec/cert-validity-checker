package route53

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	r53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
)

// DNSRecord represents a filtered DNS record from Route53.
type DNSRecord struct {
	Name       string
	Type       string
	Values     []string
	HostedZone string
}

// API defines the subset of the Route53 client used by the fetcher.
type API interface {
	ListHostedZones(ctx context.Context, params *route53.ListHostedZonesInput, optFns ...func(*route53.Options)) (*route53.ListHostedZonesOutput, error)
	ListResourceRecordSets(ctx context.Context, params *route53.ListResourceRecordSetsInput, optFns ...func(*route53.Options)) (*route53.ListResourceRecordSetsOutput, error)
}

// RecordFetcher fetches DNS records from Route53.
type RecordFetcher interface {
	FetchRecords(ctx context.Context, zoneFilter string) ([]DNSRecord, error)
}

// Fetcher implements RecordFetcher using the AWS Route53 API.
type Fetcher struct {
	client API
}

// NewFetcher creates a new Route53 record fetcher.
func NewFetcher(client API) *Fetcher {
	return &Fetcher{client: client}
}

// allowedTypes are the DNS record types we inspect for certificate validity.
var allowedTypes = map[r53types.RRType]bool{
	r53types.RRTypeA:     true,
	r53types.RRTypeAaaa:  true,
	r53types.RRTypeCname: true,
}

// FetchRecords retrieves all A, AAAA, and CNAME records across hosted zones.
// Alias records are skipped because they typically point to AWS-managed resources
// (ALBs, CloudFront) that use ACM certificates.
// If zoneFilter is non-empty, only zones whose name contains the filter string are processed.
func (f *Fetcher) FetchRecords(ctx context.Context, zoneFilter string) ([]DNSRecord, error) {
	zones, err := f.listZones(ctx, zoneFilter)
	if err != nil {
		return nil, err
	}

	var records []DNSRecord
	for _, zone := range zones {
		zoneRecords, err := f.listRecords(ctx, zone)
		if err != nil {
			return nil, err
		}
		records = append(records, zoneRecords...)
	}
	return records, nil
}

func (f *Fetcher) listZones(ctx context.Context, zoneFilter string) ([]r53types.HostedZone, error) {
	var zones []r53types.HostedZone
	var marker *string

	for {
		out, err := f.client.ListHostedZones(ctx, &route53.ListHostedZonesInput{
			Marker: marker,
		})
		if err != nil {
			return nil, err
		}

		for _, zone := range out.HostedZones {
			if zone.Config != nil && zone.Config.PrivateZone {
				continue
			}
			if zoneFilter != "" && !strings.Contains(aws.ToString(zone.Name), zoneFilter) {
				continue
			}
			zones = append(zones, zone)
		}

		if !out.IsTruncated {
			break
		}
		marker = out.NextMarker
	}
	return zones, nil
}

func (f *Fetcher) listRecords(ctx context.Context, zone r53types.HostedZone) ([]DNSRecord, error) {
	var records []DNSRecord
	zoneID := aws.ToString(zone.Id)
	zoneName := strings.TrimSuffix(aws.ToString(zone.Name), ".")

	var startName *string
	var startType r53types.RRType

	for {
		out, err := f.client.ListResourceRecordSets(ctx, &route53.ListResourceRecordSetsInput{
			HostedZoneId:    &zoneID,
			StartRecordName: startName,
			StartRecordType: startType,
		})
		if err != nil {
			return nil, err
		}

		for _, rrs := range out.ResourceRecordSets {
			if !allowedTypes[rrs.Type] {
				continue
			}
			// Skip alias records — they point to AWS-managed resources.
			if rrs.AliasTarget != nil {
				continue
			}

			name := strings.TrimSuffix(aws.ToString(rrs.Name), ".")
			var values []string
			for _, rr := range rrs.ResourceRecords {
				values = append(values, aws.ToString(rr.Value))
			}
			if len(values) == 0 {
				continue
			}

			records = append(records, DNSRecord{
				Name:       name,
				Type:       string(rrs.Type),
				Values:     values,
				HostedZone: zoneName,
			})
		}

		if !out.IsTruncated {
			break
		}
		startName = out.NextRecordName
		startType = out.NextRecordType
	}
	return records, nil
}
