package ec2

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// InstanceInfo holds identifying details about an EC2 instance.
type InstanceInfo struct {
	InstanceID string
	Name       string
	PrivateIP  string
	PublicIP   string
}

// API defines the subset of the EC2 client used by the lookup.
type API interface {
	DescribeInstances(ctx context.Context, params *ec2.DescribeInstancesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
}

// InstanceLookup resolves an IP address to EC2 instance details.
type InstanceLookup interface {
	LookupByIP(ctx context.Context, ip string) (*InstanceInfo, error)
}

// Lookup implements InstanceLookup using the EC2 API.
type Lookup struct {
	client API
}

// NewLookup creates a new EC2 instance lookup.
func NewLookup(client API) *Lookup {
	return &Lookup{client: client}
}

// LookupByIP finds the EC2 instance associated with the given IP address.
// It first searches by private IP, then by public IP.
// Returns nil (not an error) if no instance is found — the IP may belong to
// a non-EC2 resource.
func (l *Lookup) LookupByIP(ctx context.Context, ip string) (*InstanceInfo, error) {
	// Try private IP first.
	info, err := l.lookupByFilter(ctx, "private-ip-address", ip)
	if err != nil {
		return nil, err
	}
	if info != nil {
		return info, nil
	}

	// Fall back to public IP.
	return l.lookupByFilter(ctx, "ip-address", ip)
}

func (l *Lookup) lookupByFilter(ctx context.Context, filterName, ip string) (*InstanceInfo, error) {
	out, err := l.client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
		Filters: []ec2types.Filter{
			{
				Name:   aws.String(filterName),
				Values: []string{ip},
			},
		},
	})
	if err != nil {
		return nil, err
	}

	if len(out.Reservations) == 0 {
		return nil, nil
	}
	reservation := out.Reservations[0]
	if len(reservation.Instances) == 0 {
		return nil, nil
	}
	instance := reservation.Instances[0]
	info := &InstanceInfo{
		InstanceID: aws.ToString(instance.InstanceId),
		PrivateIP:  aws.ToString(instance.PrivateIpAddress),
		PublicIP:   aws.ToString(instance.PublicIpAddress),
	}
	for _, tag := range instance.Tags {
		if aws.ToString(tag.Key) == "Name" {
			info.Name = aws.ToString(tag.Value)
			break
		}
	}
	return info, nil
}
