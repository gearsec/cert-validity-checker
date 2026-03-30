package ec2

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

type mockEC2Client struct {
	instances map[string][]ec2types.Instance // keyed by filter value
}

func (m *mockEC2Client) DescribeInstances(_ context.Context, in *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	var filterValue string
	if len(in.Filters) > 0 && len(in.Filters[0].Values) > 0 {
		filterValue = in.Filters[0].Values[0]
	}

	instances, ok := m.instances[filterValue]
	if !ok {
		return &ec2.DescribeInstancesOutput{}, nil
	}

	return &ec2.DescribeInstancesOutput{
		Reservations: []ec2types.Reservation{
			{Instances: instances},
		},
	}, nil
}

func TestLookupByIP_FoundByPrivateIP(t *testing.T) {
	client := &mockEC2Client{
		instances: map[string][]ec2types.Instance{
			"10.0.1.5": {
				{
					InstanceId:       aws.String("i-abc123"),
					PrivateIpAddress: aws.String("10.0.1.5"),
					PublicIpAddress:  aws.String("54.1.2.3"),
					Tags: []ec2types.Tag{
						{Key: aws.String("Name"), Value: aws.String("web-server-1")},
					},
				},
			},
		},
	}

	lookup := NewLookup(client)
	info, err := lookup.LookupByIP(context.Background(), "10.0.1.5")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info == nil {
		t.Fatal("expected instance info, got nil")
	}
	if info.InstanceID != "i-abc123" {
		t.Errorf("expected instance ID 'i-abc123', got '%s'", info.InstanceID)
	}
	if info.Name != "web-server-1" {
		t.Errorf("expected name 'web-server-1', got '%s'", info.Name)
	}
}

func TestLookupByIP_FoundByPublicIP(t *testing.T) {
	client := &mockEC2Client{
		instances: map[string][]ec2types.Instance{
			// Not found by private IP, but found by public IP.
			"54.1.2.3": {
				{
					InstanceId:       aws.String("i-def456"),
					PrivateIpAddress: aws.String("10.0.1.10"),
					PublicIpAddress:  aws.String("54.1.2.3"),
					Tags: []ec2types.Tag{
						{Key: aws.String("Name"), Value: aws.String("api-server")},
					},
				},
			},
		},
	}

	lookup := NewLookup(client)
	info, err := lookup.LookupByIP(context.Background(), "54.1.2.3")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info == nil {
		t.Fatal("expected instance info, got nil")
	}
	if info.InstanceID != "i-def456" {
		t.Errorf("expected instance ID 'i-def456', got '%s'", info.InstanceID)
	}
}

func TestLookupByIP_NotFound(t *testing.T) {
	client := &mockEC2Client{
		instances: map[string][]ec2types.Instance{},
	}

	lookup := NewLookup(client)
	info, err := lookup.LookupByIP(context.Background(), "99.99.99.99")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info != nil {
		t.Errorf("expected nil for unknown IP, got %+v", info)
	}
}

func TestLookupByIP_NoNameTag(t *testing.T) {
	client := &mockEC2Client{
		instances: map[string][]ec2types.Instance{
			"10.0.0.1": {
				{
					InstanceId:       aws.String("i-noname"),
					PrivateIpAddress: aws.String("10.0.0.1"),
					Tags:             []ec2types.Tag{},
				},
			},
		},
	}

	lookup := NewLookup(client)
	info, err := lookup.LookupByIP(context.Background(), "10.0.0.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info == nil {
		t.Fatal("expected instance info")
	}
	if info.Name != "" {
		t.Errorf("expected empty name, got '%s'", info.Name)
	}
}
