package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cloudtrailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
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

type recordingCloudTrail struct {
	lookupAttributes [][]cloudtrailtypes.LookupAttribute
}

func (r *recordingCloudTrail) LookupEvents(_ context.Context, in *cloudtrail.LookupEventsInput, _ ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error) {
	r.lookupAttributes = append(r.lookupAttributes, in.LookupAttributes)
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

func TestSSLEnforcementRecognizesPostgreSQLForceSSL(t *testing.T) {
	client := &fakeRDS{
		parameters:        []rdstypes.Parameter{{ParameterName: aws.String("rds.force_ssl"), ParameterValue: aws.String("1")}},
		clusterParameters: []rdstypes.Parameter{{ParameterName: aws.String("rds.force_ssl"), ParameterValue: aws.String("1")}},
	}
	instance := rdstypes.DBInstance{
		DBParameterGroups: []rdstypes.DBParameterGroupStatus{{DBParameterGroupName: aws.String("postgres15")}},
	}
	cluster := rdstypes.DBCluster{DBClusterParameterGroup: aws.String("aurora-postgres15")}
	var resourceErrors []CollectionError
	var accumulated error

	instanceSSL := collectInstanceSSLEnforcement(context.Background(), client, instance, &resourceErrors, &accumulated)
	if instanceSSL["postgres15"] != "1" {
		t.Fatalf("expected instance rds.force_ssl to be normalized, got %#v", instanceSSL)
	}
	clusterSSL := collectClusterSSLEnforcement(context.Background(), client, cluster, &resourceErrors, &accumulated)
	if clusterSSL["aurora-postgres15"] != "1" {
		t.Fatalf("expected cluster rds.force_ssl to be normalized, got %#v", clusterSSL)
	}
	if accumulated != nil || len(resourceErrors) != 0 {
		t.Fatalf("unexpected SSL collection errors: %v %#v", accumulated, resourceErrors)
	}
}

func TestAssumeRoleSourceConfigUsesTargetRegion(t *testing.T) {
	base := aws.Config{Region: "", Credentials: aws.AnonymousCredentials{}}
	got := assumeRoleSourceConfig(base, "us-west-2")
	if got.Region != "us-west-2" {
		t.Fatalf("expected assume-role STS config to use target region, got %q", got.Region)
	}
	if base.Region != "" {
		t.Fatalf("base config was mutated: %#v", base)
	}
}

func TestCloudTrailCollectionUsesEventSourceQueries(t *testing.T) {
	client := &recordingCloudTrail{}
	_, err := (&Collector{}).collectCloudTrailEvents(
		context.Background(),
		client,
		time.Date(2026, 2, 13, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 5, 14, 0, 0, 0, 0, time.UTC),
	)
	if err != nil {
		t.Fatalf("collectCloudTrailEvents returned error: %v", err)
	}
	if len(client.lookupAttributes) != 2 {
		t.Fatalf("expected one lookup per event source, got %d", len(client.lookupAttributes))
	}
	for _, attrs := range client.lookupAttributes {
		if len(attrs) != 1 {
			t.Fatalf("expected one lookup attribute, got %#v", attrs)
		}
		if attrs[0].AttributeKey != cloudtrailtypes.LookupAttributeKeyEventSource {
			t.Fatalf("expected event source lookup, got %#v", attrs[0].AttributeKey)
		}
	}
}

func TestSplitCloudTrailEventsForResourceSeparatesAccountWideEvents(t *testing.T) {
	events := []map[string]interface{}{
		{
			"event_name": "ModifyDBInstance",
			"resources": []cloudtrailtypes.Resource{
				{ResourceName: aws.String("db-1")},
			},
		},
		{
			"event_name":       "DeleteDBInstance",
			"cloudtrail_event": `{"requestParameters":{"dBInstanceIdentifier":"db-1"}}`,
		},
		{
			"event_name":       "DeleteUser",
			"cloudtrail_event": `{"requestParameters":{"userName":"alice"}}`,
		},
	}
	resourceEvents, accountEvents := splitCloudTrailEventsForResource(events, "db-1", "arn:aws:rds:us-east-1:123456789012:db:db-1")
	if len(resourceEvents) != 2 {
		t.Fatalf("expected two resource events, got %#v", resourceEvents)
	}
	if len(accountEvents) != 1 || accountEvents[0]["event_name"] != "DeleteUser" {
		t.Fatalf("expected IAM event to remain account-wide, got %#v", accountEvents)
	}
}
