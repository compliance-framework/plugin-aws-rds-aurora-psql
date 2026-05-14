package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cloudwatchtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type fakeFactory struct {
	targets []ResolvedTarget
	clients map[string]AWSClientSet
}

func (f *fakeFactory) ResolveTargets(context.Context, *PluginConfig) ([]ResolvedTarget, error) {
	return f.targets, nil
}

func (f *fakeFactory) ClientsForTarget(_ context.Context, target ResolvedTarget) (AWSClientSet, error) {
	return f.clients[target.Region], nil
}

type fakeRDS struct {
	instances            []rdstypes.DBInstance
	instancesErr         error
	clusters             []rdstypes.DBCluster
	snapshots            []rdstypes.DBSnapshot
	clusterSnapshots     []rdstypes.DBClusterSnapshot
	tags                 map[string][]rdstypes.Tag
	parameters           []rdstypes.Parameter
	clusterParameters    []rdstypes.Parameter
	events               []rdstypes.Event
	snapshotAttributes   []rdstypes.DBSnapshotAttribute
	clusterSnapshotAttrs []rdstypes.DBClusterSnapshotAttribute
}

func (f *fakeRDS) DescribeDBInstances(context.Context, *rds.DescribeDBInstancesInput, ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error) {
	if f.instancesErr != nil {
		return nil, f.instancesErr
	}
	return &rds.DescribeDBInstancesOutput{DBInstances: f.instances}, nil
}

func (f *fakeRDS) DescribeDBClusters(context.Context, *rds.DescribeDBClustersInput, ...func(*rds.Options)) (*rds.DescribeDBClustersOutput, error) {
	return &rds.DescribeDBClustersOutput{DBClusters: f.clusters}, nil
}

func (f *fakeRDS) DescribeDBSnapshots(context.Context, *rds.DescribeDBSnapshotsInput, ...func(*rds.Options)) (*rds.DescribeDBSnapshotsOutput, error) {
	return &rds.DescribeDBSnapshotsOutput{DBSnapshots: f.snapshots}, nil
}

func (f *fakeRDS) DescribeDBClusterSnapshots(context.Context, *rds.DescribeDBClusterSnapshotsInput, ...func(*rds.Options)) (*rds.DescribeDBClusterSnapshotsOutput, error) {
	return &rds.DescribeDBClusterSnapshotsOutput{DBClusterSnapshots: f.clusterSnapshots}, nil
}

func (f *fakeRDS) DescribeDBSnapshotAttributes(context.Context, *rds.DescribeDBSnapshotAttributesInput, ...func(*rds.Options)) (*rds.DescribeDBSnapshotAttributesOutput, error) {
	return &rds.DescribeDBSnapshotAttributesOutput{
		DBSnapshotAttributesResult: &rdstypes.DBSnapshotAttributesResult{DBSnapshotAttributes: f.snapshotAttributes},
	}, nil
}

func (f *fakeRDS) DescribeDBClusterSnapshotAttributes(context.Context, *rds.DescribeDBClusterSnapshotAttributesInput, ...func(*rds.Options)) (*rds.DescribeDBClusterSnapshotAttributesOutput, error) {
	return &rds.DescribeDBClusterSnapshotAttributesOutput{
		DBClusterSnapshotAttributesResult: &rdstypes.DBClusterSnapshotAttributesResult{DBClusterSnapshotAttributes: f.clusterSnapshotAttrs},
	}, nil
}

func (f *fakeRDS) DescribeDBParameters(context.Context, *rds.DescribeDBParametersInput, ...func(*rds.Options)) (*rds.DescribeDBParametersOutput, error) {
	return &rds.DescribeDBParametersOutput{Parameters: f.parameters}, nil
}

func (f *fakeRDS) DescribeDBClusterParameters(context.Context, *rds.DescribeDBClusterParametersInput, ...func(*rds.Options)) (*rds.DescribeDBClusterParametersOutput, error) {
	return &rds.DescribeDBClusterParametersOutput{Parameters: f.clusterParameters}, nil
}

func (f *fakeRDS) DescribeEvents(context.Context, *rds.DescribeEventsInput, ...func(*rds.Options)) (*rds.DescribeEventsOutput, error) {
	return &rds.DescribeEventsOutput{Events: f.events}, nil
}

func (f *fakeRDS) ListTagsForResource(_ context.Context, in *rds.ListTagsForResourceInput, _ ...func(*rds.Options)) (*rds.ListTagsForResourceOutput, error) {
	return &rds.ListTagsForResourceOutput{TagList: f.tags[aws.ToString(in.ResourceName)]}, nil
}

type fakeCloudTrail struct{}

func (f *fakeCloudTrail) LookupEvents(context.Context, *cloudtrail.LookupEventsInput, ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error) {
	return &cloudtrail.LookupEventsOutput{}, nil
}

type fakeCloudWatch struct{}

func (f *fakeCloudWatch) GetMetricData(context.Context, *cloudwatch.GetMetricDataInput, ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricDataOutput, error) {
	return &cloudwatch.GetMetricDataOutput{MetricDataResults: []cloudwatchtypes.MetricDataResult{}}, nil
}

type fakeSTS struct {
	account string
}

func (f *fakeSTS) GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	return &sts.GetCallerIdentityOutput{Account: aws.String(f.account)}, nil
}

func TestCollectorContinuesAfterTargetFailure(t *testing.T) {
	cfg, err := parsePluginConfig(map[string]string{
		"max_concurrency":     "1",
		"api_timeout_seconds": "5",
		"policy_inputs":       `{"minimum_backup_retention_days":7}`,
	})
	if err != nil {
		t.Fatalf("parsePluginConfig returned error: %v", err)
	}
	now := time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC)
	goodInstanceARN := "arn:aws:rds:us-west-2:222222222222:db:db-ok"
	factory := &fakeFactory{
		targets: []ResolvedTarget{
			{Account: AccountContext{AccountID: "111111111111"}, Region: "us-east-1"},
			{Account: AccountContext{AccountID: "222222222222"}, Region: "us-west-2"},
		},
		clients: map[string]AWSClientSet{
			"us-east-1": {
				RDS:        &fakeRDS{instancesErr: errors.New("access denied")},
				CloudTrail: &fakeCloudTrail{},
				CloudWatch: &fakeCloudWatch{},
				STS:        &fakeSTS{account: "111111111111"},
			},
			"us-west-2": {
				RDS: &fakeRDS{
					instances: []rdstypes.DBInstance{
						{
							DBInstanceIdentifier:  aws.String("db-ok"),
							DBInstanceArn:         aws.String(goodInstanceARN),
							Engine:                aws.String("postgres"),
							StorageEncrypted:      aws.Bool(true),
							KmsKeyId:              aws.String("arn:aws:kms:us-west-2:222222222222:key/key-id"),
							BackupRetentionPeriod: aws.Int32(7),
							DBParameterGroups: []rdstypes.DBParameterGroupStatus{
								{DBParameterGroupName: aws.String("default.postgres15")},
							},
						},
					},
					tags: map[string][]rdstypes.Tag{
						goodInstanceARN: {{Key: aws.String("owner"), Value: aws.String("data")}},
					},
					parameters: []rdstypes.Parameter{{ParameterName: aws.String("require_ssl"), ParameterValue: aws.String("1")}},
				},
				CloudTrail: &fakeCloudTrail{},
				CloudWatch: &fakeCloudWatch{},
				STS:        &fakeSTS{account: "222222222222"},
			},
		},
	}
	result := (&Collector{Config: cfg, Factory: factory, Now: func() time.Time { return now }}).Collect(context.Background())
	if result.Err == nil {
		t.Fatal("expected accumulated error from failed target")
	}
	if len(result.Records) != 1 {
		t.Fatalf("expected one record from healthy target, got %d", len(result.Records))
	}
	record := result.Records[0]
	if record.Input.Account.AccountID != "222222222222" || record.Input.Region.Name != "us-west-2" {
		t.Fatalf("unexpected account/region: %#v %#v", record.Input.Account, record.Input.Region)
	}
	if record.Input.PolicyInputs["minimum_backup_retention_days"].(float64) != 7 {
		t.Fatalf("policy inputs were not nested under input.policy_inputs: %#v", record.Input.PolicyInputs)
	}
	if record.Input.Config["ssl_enforcement"].(map[string]string)["default.postgres15"] != "1" {
		t.Fatalf("expected require_ssl normalization, got %#v", record.Input.Config["ssl_enforcement"])
	}
	if _, ok := record.Labels["primary"]; ok {
		t.Fatal("raw payload hash leaked into labels")
	}
	if len(record.Input.Collection.RawPayloadHashes) == 0 {
		t.Fatal("expected raw payload hash under collection.raw_payload_hashes")
	}
}
