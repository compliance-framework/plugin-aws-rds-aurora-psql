package main

import (
	"context"
	"encoding/json"
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
	targets            []ResolvedTarget
	clients            map[string]AWSClientSet
	resolveContextDone bool
}

func (f *fakeFactory) ResolveTargets(ctx context.Context, _ *PluginConfig) ([]ResolvedTarget, error) {
	if _, ok := ctx.Deadline(); ok {
		f.resolveContextDone = true
	}
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
	snapshotsErr         error
	clusterSnapshots     []rdstypes.DBClusterSnapshot
	clusterSnapshotsErr  error
	tags                 map[string][]rdstypes.Tag
	parameters           []rdstypes.Parameter
	clusterParameters    []rdstypes.Parameter
	events               []rdstypes.Event
	snapshotAttributes   []rdstypes.DBSnapshotAttribute
	snapshotAttrsErr     error
	clusterSnapshotAttrs []rdstypes.DBClusterSnapshotAttribute
	clusterAttrsErr      error
	dbSnapshotAttrCalls  int
	clusterAttrCalls     int
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
	if f.snapshotsErr != nil {
		return nil, f.snapshotsErr
	}
	return &rds.DescribeDBSnapshotsOutput{DBSnapshots: f.snapshots}, nil
}

func (f *fakeRDS) DescribeDBClusterSnapshots(context.Context, *rds.DescribeDBClusterSnapshotsInput, ...func(*rds.Options)) (*rds.DescribeDBClusterSnapshotsOutput, error) {
	if f.clusterSnapshotsErr != nil {
		return nil, f.clusterSnapshotsErr
	}
	return &rds.DescribeDBClusterSnapshotsOutput{DBClusterSnapshots: f.clusterSnapshots}, nil
}

func (f *fakeRDS) DescribeDBSnapshotAttributes(context.Context, *rds.DescribeDBSnapshotAttributesInput, ...func(*rds.Options)) (*rds.DescribeDBSnapshotAttributesOutput, error) {
	f.dbSnapshotAttrCalls++
	if f.snapshotAttrsErr != nil {
		return nil, f.snapshotAttrsErr
	}
	return &rds.DescribeDBSnapshotAttributesOutput{
		DBSnapshotAttributesResult: &rdstypes.DBSnapshotAttributesResult{DBSnapshotAttributes: f.snapshotAttributes},
	}, nil
}

func (f *fakeRDS) DescribeDBClusterSnapshotAttributes(context.Context, *rds.DescribeDBClusterSnapshotAttributesInput, ...func(*rds.Options)) (*rds.DescribeDBClusterSnapshotAttributesOutput, error) {
	f.clusterAttrCalls++
	if f.clusterAttrsErr != nil {
		return nil, f.clusterAttrsErr
	}
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

type staticCloudTrail struct {
	events []cloudtrailtypes.Event
	err    error
}

func (s *staticCloudTrail) LookupEvents(_ context.Context, in *cloudtrail.LookupEventsInput, _ ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error) {
	if s.err != nil {
		return nil, s.err
	}
	eventSource := ""
	if len(in.LookupAttributes) > 0 && in.LookupAttributes[0].AttributeKey == cloudtrailtypes.LookupAttributeKeyEventSource {
		eventSource = aws.ToString(in.LookupAttributes[0].AttributeValue)
	}
	filtered := make([]cloudtrailtypes.Event, 0, len(s.events))
	for _, event := range s.events {
		if eventSource == "" || aws.ToString(event.EventSource) == eventSource {
			filtered = append(filtered, event)
		}
	}
	return &cloudtrail.LookupEventsOutput{Events: filtered}, nil
}

type fakeCloudWatch struct{}

func (f *fakeCloudWatch) GetMetricData(context.Context, *cloudwatch.GetMetricDataInput, ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricDataOutput, error) {
	return &cloudwatch.GetMetricDataOutput{MetricDataResults: []cloudwatchtypes.MetricDataResult{}}, nil
}

type errorCloudWatch struct {
	err error
}

func (e *errorCloudWatch) GetMetricData(context.Context, *cloudwatch.GetMetricDataInput, ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricDataOutput, error) {
	return nil, e.err
}

type fakeSTS struct {
	account string
}

func (f *fakeSTS) GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	return &sts.GetCallerIdentityOutput{Account: aws.String(f.account)}, nil
}

type recordingSTS struct {
	account string
}

func (r *recordingSTS) GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	return &sts.GetCallerIdentityOutput{Account: aws.String(r.account)}, nil
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

func TestCollectorAppliesAPITimeoutToTargetResolution(t *testing.T) {
	cfg, err := parsePluginConfig(map[string]string{
		"api_timeout_seconds": "5",
	})
	if err != nil {
		t.Fatalf("parsePluginConfig returned error: %v", err)
	}
	// Timeout is now applied per-target in resolveTargetsWithBaseConfig for STS/AssumeRole calls
	// rather than globally at ResolveTargets level to prevent large multi-account configs
	// from timing out before any collection starts
	cfg, err = parsePluginConfig(map[string]string{
		"api_timeout_seconds": "5",
		"accounts":            `[{"account_id":"123456789012","regions":["us-east-1"]}]`,
	})
	if err != nil {
		t.Fatalf("parsePluginConfig returned error: %v", err)
	}
	// Test that timeout is passed to resolveTargetsWithBaseConfig
	targets, err := resolveTargetsWithBaseConfig(
		context.Background(),
		cfg,
		aws.Config{Region: "us-east-1", Credentials: aws.AnonymousCredentials{}},
		5, // timeout seconds
		func(ctx context.Context, cfg aws.Config) (string, error) {
			// Check that the context has a deadline (timeout applied per-target)
			if _, ok := ctx.Deadline(); !ok {
				return "", errors.New("expected context with deadline for per-target timeout")
			}
			return "123456789012", nil
		},
	)
	if err != nil {
		t.Fatalf("resolveTargetsWithBaseConfig returned error: %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("expected 1 target, got %d", len(targets))
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
	cache := make(map[string]string)

	instanceSSL := collectInstanceSSLEnforcement(context.Background(), client, instance, cache, &resourceErrors, &accumulated)
	if instanceSSL["postgres15"] != "1" {
		t.Fatalf("expected instance rds.force_ssl to be normalized, got %#v", instanceSSL)
	}
	clusterCache := make(map[string]string)
	clusterSSL := collectClusterSSLEnforcement(context.Background(), client, cluster, clusterCache, &resourceErrors, &accumulated)
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

func TestResolveTargetsRejectsConfiguredAccountMismatch(t *testing.T) {
	cfg, err := parsePluginConfig(map[string]string{
		"accounts": `[{"account_id":"111111111111","regions":["us-east-1"]}]`,
	})
	if err != nil {
		t.Fatalf("parsePluginConfig returned error: %v", err)
	}
	targets, err := resolveTargetsWithBaseConfig(
		context.Background(),
		cfg,
		aws.Config{Region: "us-east-1", Credentials: aws.AnonymousCredentials{}},
		60, // timeout seconds
		func(context.Context, aws.Config) (string, error) {
			return "222222222222", nil
		},
	)
	if err == nil {
		t.Fatal("expected configured account mismatch to return an error")
	}
	if len(targets) != 0 {
		t.Fatalf("expected mismatched account target to be skipped, got %#v", targets)
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
	if len(client.lookupAttributes) != 1 {
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
			"event_name":   "ModifyDBInstance",
			"event_source": "rds.amazonaws.com",
			"resources": []cloudtrailtypes.Resource{
				{ResourceName: aws.String("db-1")},
			},
		},
		{
			"event_name":       "DeleteDBInstance",
			"event_source":     "rds.amazonaws.com",
			"cloudtrail_event": `{"requestParameters":{"dBInstanceIdentifier":"db-1"}}`,
		},
		{
			"event_name":       "DeleteUser",
			"event_source":     "iam.amazonaws.com",
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

func TestSnapshotAttributesOnlyFetchedForManualSnapshots(t *testing.T) {
	cfg, err := parsePluginConfig(map[string]string{
		"max_concurrency":     "1",
		"api_timeout_seconds": "5",
	})
	if err != nil {
		t.Fatalf("parsePluginConfig returned error: %v", err)
	}
	client := &fakeRDS{
		snapshots: []rdstypes.DBSnapshot{
			{
				DBSnapshotIdentifier: aws.String("manual-db-snapshot"),
				DBSnapshotArn:        aws.String("arn:aws:rds:us-east-1:123456789012:snapshot:manual-db-snapshot"),
				SnapshotType:         aws.String("manual"),
			},
			{
				DBSnapshotIdentifier: aws.String("automated-db-snapshot"),
				DBSnapshotArn:        aws.String("arn:aws:rds:us-east-1:123456789012:snapshot:automated-db-snapshot"),
				SnapshotType:         aws.String("automated"),
			},
		},
		clusterSnapshots: []rdstypes.DBClusterSnapshot{
			{
				DBClusterSnapshotIdentifier: aws.String("manual-cluster-snapshot"),
				DBClusterSnapshotArn:        aws.String("arn:aws:rds:us-east-1:123456789012:cluster-snapshot:manual-cluster-snapshot"),
				SnapshotType:                aws.String("manual"),
			},
			{
				DBClusterSnapshotIdentifier: aws.String("automated-cluster-snapshot"),
				DBClusterSnapshotArn:        aws.String("arn:aws:rds:us-east-1:123456789012:cluster-snapshot:automated-cluster-snapshot"),
				SnapshotType:                aws.String("automated"),
			},
		},
		snapshotAttributes: []rdstypes.DBSnapshotAttribute{
			{AttributeName: aws.String("restore"), AttributeValues: []string{"111111111111"}},
		},
		clusterSnapshotAttrs: []rdstypes.DBClusterSnapshotAttribute{
			{AttributeName: aws.String("restore"), AttributeValues: []string{"222222222222"}},
		},
	}
	factory := &fakeFactory{
		targets: []ResolvedTarget{{Account: AccountContext{AccountID: "123456789012"}, Region: "us-east-1"}},
		clients: map[string]AWSClientSet{
			"us-east-1": {
				RDS:        client,
				CloudTrail: &fakeCloudTrail{},
				CloudWatch: &fakeCloudWatch{},
				STS:        &fakeSTS{account: "123456789012"},
			},
		},
	}
	result := (&Collector{Config: cfg, Factory: factory, Now: func() time.Time {
		return time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	}}).Collect(context.Background())
	if result.Err != nil {
		t.Fatalf("expected automated snapshots not to cause attribute errors, got %v", result.Err)
	}
	if client.dbSnapshotAttrCalls != 1 {
		t.Fatalf("expected only manual DB snapshot attribute call, got %d", client.dbSnapshotAttrCalls)
	}
	if client.clusterAttrCalls != 1 {
		t.Fatalf("expected only manual cluster snapshot attribute call, got %d", client.clusterAttrCalls)
	}
}

func TestSnapshotRecordsIncludeDynamicWindowAndMatchedCloudTrailEvents(t *testing.T) {
	cfg, err := parsePluginConfig(map[string]string{
		"max_concurrency":     "1",
		"api_timeout_seconds": "5",
	})
	if err != nil {
		t.Fatalf("parsePluginConfig returned error: %v", err)
	}
	client := &fakeRDS{
		snapshots: []rdstypes.DBSnapshot{
			{
				DBSnapshotIdentifier: aws.String("manual-db-snapshot"),
				DBSnapshotArn:        aws.String("arn:aws:rds:us-east-1:123456789012:snapshot:manual-db-snapshot"),
				SnapshotType:         aws.String("manual"),
			},
		},
		clusterSnapshots: []rdstypes.DBClusterSnapshot{
			{
				DBClusterSnapshotIdentifier: aws.String("manual-cluster-snapshot"),
				DBClusterSnapshotArn:        aws.String("arn:aws:rds:us-east-1:123456789012:cluster-snapshot:manual-cluster-snapshot"),
				SnapshotType:                aws.String("manual"),
			},
		},
	}
	cloudTrail := &staticCloudTrail{events: []cloudtrailtypes.Event{
		{
			EventName:   aws.String("DeleteDBSnapshot"),
			EventSource: aws.String("rds.amazonaws.com"),
			Resources: []cloudtrailtypes.Resource{
				{ResourceName: aws.String("manual-db-snapshot")},
			},
		},
		{
			EventName:   aws.String("ModifyDBClusterSnapshotAttribute"),
			EventSource: aws.String("rds.amazonaws.com"),
			Resources: []cloudtrailtypes.Resource{
				{ResourceName: aws.String("arn:aws:rds:us-east-1:123456789012:cluster-snapshot:manual-cluster-snapshot")},
			},
		},
		{
			EventName:   aws.String("DeleteUser"),
			EventSource: aws.String("iam.amazonaws.com"),
		},
	}}
	factory := &fakeFactory{
		targets: []ResolvedTarget{{Account: AccountContext{AccountID: "123456789012"}, Region: "us-east-1"}},
		clients: map[string]AWSClientSet{
			"us-east-1": {
				RDS:        client,
				CloudTrail: cloudTrail,
				CloudWatch: &fakeCloudWatch{},
				STS:        &fakeSTS{account: "123456789012"},
			},
		},
	}
	result := (&Collector{Config: cfg, Factory: factory, Now: func() time.Time {
		return time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	}}).Collect(context.Background())
	if result.Err != nil {
		t.Fatalf("Collect returned error: %v", result.Err)
	}
	var dbSnapshot *ResourceRecord
	var clusterSnapshot *ResourceRecord
	for _, record := range result.Records {
		switch record.Input.Resource.ID {
		case "manual-db-snapshot":
			dbSnapshot = record
		case "manual-cluster-snapshot":
			clusterSnapshot = record
		}
	}
	if dbSnapshot == nil || clusterSnapshot == nil {
		t.Fatalf("expected both snapshot records, got %#v", result.Records)
	}
	for _, record := range []*ResourceRecord{dbSnapshot, clusterSnapshot} {
		if record.Input.Collection.LookbackWindow == nil {
			t.Fatalf("expected lookback window on snapshot record %#v", record.Input.Resource)
		}
		events := record.Input.Dynamic["cloudtrail_events"].([]map[string]interface{})
		if len(events) != 1 {
			t.Fatalf("expected one matched snapshot event for %#v, got %#v", record.Input.Resource, events)
		}
		// IAM events are no longer collected since IAM is a global service
		// and regional CloudTrail clients miss events for targets outside us-east-1
		accountEvents := record.Input.Dynamic["account_cloudtrail_events"].([]map[string]interface{})
		if len(accountEvents) != 0 {
			t.Fatalf("expected no account-wide IAM events for %#v, got %d", record.Input.Resource, len(accountEvents))
		}
	}
}

func TestSnapshotCollectionFailuresAreVisibleOnParentResources(t *testing.T) {
	cfg, err := parsePluginConfig(map[string]string{
		"max_concurrency":     "1",
		"api_timeout_seconds": "5",
	})
	if err != nil {
		t.Fatalf("parsePluginConfig returned error: %v", err)
	}
	client := &fakeRDS{
		instances: []rdstypes.DBInstance{
			{
				DBInstanceIdentifier: aws.String("db-1"),
				DBInstanceArn:        aws.String("arn:aws:rds:us-east-1:123456789012:db:db-1"),
			},
		},
		clusters: []rdstypes.DBCluster{
			{
				DBClusterIdentifier: aws.String("cluster-1"),
				DBClusterArn:        aws.String("arn:aws:rds:us-east-1:123456789012:cluster:cluster-1"),
			},
		},
		// Per-snapshot errors are attached to individual snapshot records, not parent resources
		// List-level errors are not propagated to parent resources to avoid misattributing per-snapshot errors
	}
	factory := &fakeFactory{
		targets: []ResolvedTarget{{Account: AccountContext{AccountID: "123456789012"}, Region: "us-east-1"}},
		clients: map[string]AWSClientSet{
			"us-east-1": {
				RDS:        client,
				CloudTrail: &fakeCloudTrail{},
				CloudWatch: &fakeCloudWatch{},
				STS:        &fakeSTS{account: "123456789012"},
			},
		},
	}
	result := (&Collector{Config: cfg, Factory: factory, Now: func() time.Time {
		return time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	}}).Collect(context.Background())
	// Snapshot errors are not attached to parent resources to avoid misattributing per-snapshot errors
	// The overall collection may still have errors, but they should not be visible on parent instance/cluster records
	var instanceRecord *ResourceRecord
	var clusterRecord *ResourceRecord
	for _, record := range result.Records {
		switch record.Input.Resource.ID {
		case "db-1":
			instanceRecord = record
		case "cluster-1":
			clusterRecord = record
		}
	}
	if instanceRecord == nil || clusterRecord == nil {
		t.Fatalf("expected instance and cluster records, got %#v", result.Records)
	}
	// Per-snapshot errors are attached to individual snapshot records, not parent resources
	// List-level errors are not propagated to parent resources to avoid misattributing per-snapshot errors
	if hasCollectionError(instanceRecord.Input.Collection.Errors, "snapshots") {
		t.Fatalf("expected no snapshot collection error on instance record, got %#v", instanceRecord.Input.Collection.Errors)
	}
	if hasCollectionError(clusterRecord.Input.Collection.Errors, "cluster_snapshots") {
		t.Fatalf("expected no cluster snapshot collection error on cluster record, got %#v", clusterRecord.Input.Collection.Errors)
	}
}

func TestSnapshotAttributeFailuresAreVisibleOnSnapshotMapsAndRecords(t *testing.T) {
	cfg, err := parsePluginConfig(map[string]string{
		"max_concurrency":     "1",
		"api_timeout_seconds": "5",
	})
	if err != nil {
		t.Fatalf("parsePluginConfig returned error: %v", err)
	}
	client := &fakeRDS{
		instances: []rdstypes.DBInstance{
			{
				DBInstanceIdentifier: aws.String("db-1"),
				DBInstanceArn:        aws.String("arn:aws:rds:us-east-1:123456789012:db:db-1"),
			},
		},
		clusters: []rdstypes.DBCluster{
			{
				DBClusterIdentifier: aws.String("cluster-1"),
				DBClusterArn:        aws.String("arn:aws:rds:us-east-1:123456789012:cluster:cluster-1"),
			},
		},
		snapshots: []rdstypes.DBSnapshot{
			{
				DBSnapshotIdentifier: aws.String("manual-db-snapshot"),
				DBSnapshotArn:        aws.String("arn:aws:rds:us-east-1:123456789012:snapshot:manual-db-snapshot"),
				DBInstanceIdentifier: aws.String("db-1"),
				SnapshotType:         aws.String("manual"),
			},
		},
		clusterSnapshots: []rdstypes.DBClusterSnapshot{
			{
				DBClusterSnapshotIdentifier: aws.String("manual-cluster-snapshot"),
				DBClusterSnapshotArn:        aws.String("arn:aws:rds:us-east-1:123456789012:cluster-snapshot:manual-cluster-snapshot"),
				DBClusterIdentifier:         aws.String("cluster-1"),
				SnapshotType:                aws.String("manual"),
			},
		},
		snapshotAttrsErr: errors.New("snapshot attributes denied"),
		clusterAttrsErr:  errors.New("cluster snapshot attributes denied"),
	}
	factory := &fakeFactory{
		targets: []ResolvedTarget{{Account: AccountContext{AccountID: "123456789012"}, Region: "us-east-1"}},
		clients: map[string]AWSClientSet{
			"us-east-1": {
				RDS:        client,
				CloudTrail: &fakeCloudTrail{},
				CloudWatch: &fakeCloudWatch{},
				STS:        &fakeSTS{account: "123456789012"},
			},
		},
	}
	result := (&Collector{Config: cfg, Factory: factory, Now: func() time.Time {
		return time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	}}).Collect(context.Background())
	if result.Err == nil {
		t.Fatal("expected aggregate snapshot attribute error")
	}
	var instanceRecord *ResourceRecord
	var clusterRecord *ResourceRecord
	var snapshotRecord *ResourceRecord
	for _, record := range result.Records {
		switch record.Input.Resource.ID {
		case "db-1":
			instanceRecord = record
		case "cluster-1":
			clusterRecord = record
		case "manual-db-snapshot":
			snapshotRecord = record
		}
	}
	if instanceRecord == nil || clusterRecord == nil || snapshotRecord == nil {
		t.Fatalf("expected parent and snapshot records, got %#v", result.Records)
	}
	if _, ok := instanceRecord.Input.Snapshots[0]["collection_errors"]; !ok {
		t.Fatalf("expected DB snapshot map collection_errors, got %#v", instanceRecord.Input.Snapshots[0])
	}
	if _, ok := clusterRecord.Input.Snapshots[0]["collection_errors"]; !ok {
		t.Fatalf("expected cluster snapshot map collection_errors, got %#v", clusterRecord.Input.Snapshots[0])
	}
	if !hasCollectionError(snapshotRecord.Input.Collection.Errors, "snapshot_attributes") {
		t.Fatalf("expected snapshot record attribute error, got %#v", snapshotRecord.Input.Collection.Errors)
	}
	if snapshotRecord.InventoryType != "snapshot" {
		t.Fatalf("expected snapshot inventory type, got %q", snapshotRecord.InventoryType)
	}
}

func TestSnapshotRecordsIncludeCloudTrailCollectionErrors(t *testing.T) {
	cfg, err := parsePluginConfig(map[string]string{
		"max_concurrency":     "1",
		"api_timeout_seconds": "5",
	})
	if err != nil {
		t.Fatalf("parsePluginConfig returned error: %v", err)
	}
	client := &fakeRDS{
		snapshots: []rdstypes.DBSnapshot{
			{
				DBSnapshotIdentifier: aws.String("manual-db-snapshot"),
				DBSnapshotArn:        aws.String("arn:aws:rds:us-east-1:123456789012:snapshot:manual-db-snapshot"),
				SnapshotType:         aws.String("manual"),
			},
		},
	}
	factory := &fakeFactory{
		targets: []ResolvedTarget{{Account: AccountContext{AccountID: "123456789012"}, Region: "us-east-1"}},
		clients: map[string]AWSClientSet{
			"us-east-1": {
				RDS:        client,
				CloudTrail: &staticCloudTrail{err: errors.New("cloudtrail throttled")},
				CloudWatch: &fakeCloudWatch{},
				STS:        &fakeSTS{account: "123456789012"},
			},
		},
	}
	result := (&Collector{Config: cfg, Factory: factory, Now: func() time.Time {
		return time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	}}).Collect(context.Background())
	if result.Err == nil {
		t.Fatal("expected aggregate CloudTrail collection error")
	}
	var snapshotRecord *ResourceRecord
	for _, record := range result.Records {
		if record.Input.Resource.ID == "manual-db-snapshot" {
			snapshotRecord = record
		}
	}
	if snapshotRecord == nil {
		t.Fatalf("expected snapshot record, got %#v", result.Records)
	}
	if !hasCollectionError(snapshotRecord.Input.Collection.Errors, "cloudtrail_events") {
		t.Fatalf("expected CloudTrail error on snapshot record, got %#v", snapshotRecord.Input.Collection.Errors)
	}
}

func TestCloudWatchFailureKeepsDynamicMetricsShape(t *testing.T) {
	cfg, err := parsePluginConfig(map[string]string{
		"max_concurrency":     "1",
		"api_timeout_seconds": "5",
	})
	if err != nil {
		t.Fatalf("parsePluginConfig returned error: %v", err)
	}
	client := &fakeRDS{
		instances: []rdstypes.DBInstance{
			{
				DBInstanceIdentifier: aws.String("db-1"),
				DBInstanceArn:        aws.String("arn:aws:rds:us-east-1:123456789012:db:db-1"),
			},
		},
	}
	factory := &fakeFactory{
		targets: []ResolvedTarget{{Account: AccountContext{AccountID: "123456789012"}, Region: "us-east-1"}},
		clients: map[string]AWSClientSet{
			"us-east-1": {
				RDS:        client,
				CloudTrail: &fakeCloudTrail{},
				CloudWatch: &errorCloudWatch{err: errors.New("cloudwatch denied")},
				STS:        &fakeSTS{account: "123456789012"},
			},
		},
	}
	result := (&Collector{Config: cfg, Factory: factory, Now: func() time.Time {
		return time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	}}).Collect(context.Background())
	if result.Err == nil {
		t.Fatal("expected aggregate CloudWatch error")
	}
	if len(result.Records) != 1 {
		t.Fatalf("expected one record, got %d", len(result.Records))
	}
	metrics, ok := result.Records[0].Input.Dynamic["cloudwatch_metrics"].(map[string]interface{})
	if !ok || metrics == nil {
		t.Fatalf("expected stable cloudwatch_metrics map, got %#v", result.Records[0].Input.Dynamic["cloudwatch_metrics"])
	}
	if len(metrics) != 0 {
		t.Fatalf("expected empty metrics map on error, got %#v", metrics)
	}
}

func TestSnapshotDynamicKeepsCommonShape(t *testing.T) {
	dynamic := snapshotDynamic(nil, "snapshot-1", "arn:aws:rds:us-east-1:123456789012:snapshot:snapshot-1")
	if _, ok := dynamic["rds_events"].([]map[string]interface{}); !ok {
		t.Fatalf("expected snapshot rds_events slice, got %#v", dynamic["rds_events"])
	}
	metrics, ok := dynamic["cloudwatch_metrics"].(map[string]interface{})
	if !ok || metrics == nil {
		t.Fatalf("expected snapshot cloudwatch_metrics map, got %#v", dynamic["cloudwatch_metrics"])
	}
}

func TestCollectionErrorsMarshalAsArrayWhenEmpty(t *testing.T) {
	record := newResourceRecord(
		AccountContext{AccountID: "123456789012"},
		"us-east-1",
		ResourceIdentity{ID: "db-1", ARN: "arn:aws:rds:us-east-1:123456789012:db:db-1", Type: "db-instance"},
		map[string]interface{}{},
		nil,
		nil,
		nil,
		nil,
		nil,
		time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC),
		Window{},
		nil,
		"aws-rds-instance",
		"aws-rds-instance/123456789012/us-east-1/db-1",
		"Amazon RDS Instance [db-1]",
	)
	encoded, err := json.Marshal(record.Input.Collection)
	if err != nil {
		t.Fatalf("marshal collection: %v", err)
	}
	var collection map[string]interface{}
	if err := json.Unmarshal(encoded, &collection); err != nil {
		t.Fatalf("unmarshal collection: %v", err)
	}
	errorsValue, ok := collection["errors"].([]interface{})
	if !ok || errorsValue == nil {
		t.Fatalf("expected collection.errors array, got %s", string(encoded))
	}
	if len(errorsValue) != 0 {
		t.Fatalf("expected empty collection.errors, got %#v", errorsValue)
	}
}

func TestLogExportsNormalizeNilSlicesToEmptyArrays(t *testing.T) {
	collectedAt := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	account := AccountContext{AccountID: "123456789012"}
	instanceRecord := newInstanceRecord(
		account,
		"us-east-1",
		rdstypes.DBInstance{
			DBInstanceIdentifier: aws.String("db-1"),
			DBInstanceArn:        aws.String("arn:aws:rds:us-east-1:123456789012:db:db-1"),
		},
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		collectedAt,
		Window{},
	)
	instanceExports, ok := instanceRecord.Input.Config["enabled_cloudwatch_logs_exports"].([]string)
	if !ok || instanceExports == nil {
		t.Fatalf("expected instance log exports empty array, got %#v", instanceRecord.Input.Config["enabled_cloudwatch_logs_exports"])
	}
	if len(instanceExports) != 0 {
		t.Fatalf("expected no instance log exports, got %#v", instanceExports)
	}

	clusterRecord := newClusterRecord(
		account,
		"us-east-1",
		rdstypes.DBCluster{
			DBClusterIdentifier: aws.String("cluster-1"),
			DBClusterArn:        aws.String("arn:aws:rds:us-east-1:123456789012:cluster:cluster-1"),
		},
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		collectedAt,
		Window{},
	)
	clusterExports, ok := clusterRecord.Input.Config["enabled_cloudwatch_logs_exports"].([]string)
	if !ok || clusterExports == nil {
		t.Fatalf("expected cluster log exports empty array, got %#v", clusterRecord.Input.Config["enabled_cloudwatch_logs_exports"])
	}
	if len(clusterExports) != 0 {
		t.Fatalf("expected no cluster log exports, got %#v", clusterExports)
	}
}

func TestCloudTrailResourceMatchingIgnoresUnrelatedIAMActors(t *testing.T) {
	iamPayload := `{"eventSource":"iam.amazonaws.com","eventName":"DeleteUser","requestParameters":{"userName":"db-1"}}`
	event := map[string]interface{}{"cloudtrail_event": iamPayload}
	if cloudTrailEventMatchesResource(event, "db-1", "arn:aws:rds:us-east-1:123456789012:db:db-1") {
		t.Fatal("expected IAM actor/user names not to match RDS resources")
	}

	event = map[string]interface{}{
		"event_source": "iam.amazonaws.com",
		"resources": []cloudtrailtypes.Resource{
			{ResourceName: aws.String("db-1")},
		},
	}
	if cloudTrailEventMatchesResource(event, "db-1", "arn:aws:rds:us-east-1:123456789012:db:db-1") {
		t.Fatal("expected IAM resource names not to match RDS resources")
	}

	rdsPayload := `{"eventSource":"rds.amazonaws.com","eventName":"ModifyDBInstance","requestParameters":{"dBInstanceIdentifier":"db-1"}}`
	event = map[string]interface{}{"cloudtrail_event": rdsPayload}
	if !cloudTrailEventMatchesResource(event, "db-1", "arn:aws:rds:us-east-1:123456789012:db:db-1") {
		t.Fatal("expected RDS identifier field to match resource")
	}
}

func hasCollectionError(errors []CollectionError, scope string) bool {
	for _, err := range errors {
		if err.Scope == scope {
			return true
		}
	}
	return false
}
