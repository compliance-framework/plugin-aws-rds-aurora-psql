package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cloudtrailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cloudwatchtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/hashicorp/go-hclog"
)

type RDSAPI interface {
	DescribeDBInstances(context.Context, *rds.DescribeDBInstancesInput, ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error)
	DescribeDBClusters(context.Context, *rds.DescribeDBClustersInput, ...func(*rds.Options)) (*rds.DescribeDBClustersOutput, error)
	DescribeDBSnapshots(context.Context, *rds.DescribeDBSnapshotsInput, ...func(*rds.Options)) (*rds.DescribeDBSnapshotsOutput, error)
	DescribeDBClusterSnapshots(context.Context, *rds.DescribeDBClusterSnapshotsInput, ...func(*rds.Options)) (*rds.DescribeDBClusterSnapshotsOutput, error)
	DescribeDBSnapshotAttributes(context.Context, *rds.DescribeDBSnapshotAttributesInput, ...func(*rds.Options)) (*rds.DescribeDBSnapshotAttributesOutput, error)
	DescribeDBClusterSnapshotAttributes(context.Context, *rds.DescribeDBClusterSnapshotAttributesInput, ...func(*rds.Options)) (*rds.DescribeDBClusterSnapshotAttributesOutput, error)
	DescribeDBParameters(context.Context, *rds.DescribeDBParametersInput, ...func(*rds.Options)) (*rds.DescribeDBParametersOutput, error)
	DescribeDBClusterParameters(context.Context, *rds.DescribeDBClusterParametersInput, ...func(*rds.Options)) (*rds.DescribeDBClusterParametersOutput, error)
	DescribeEvents(context.Context, *rds.DescribeEventsInput, ...func(*rds.Options)) (*rds.DescribeEventsOutput, error)
	ListTagsForResource(context.Context, *rds.ListTagsForResourceInput, ...func(*rds.Options)) (*rds.ListTagsForResourceOutput, error)
}

type CloudTrailAPI interface {
	LookupEvents(context.Context, *cloudtrail.LookupEventsInput, ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error)
}

type CloudWatchAPI interface {
	GetMetricData(context.Context, *cloudwatch.GetMetricDataInput, ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricDataOutput, error)
}

type STSAPI interface {
	GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

type AWSClientSet struct {
	RDS        RDSAPI
	CloudTrail CloudTrailAPI
	CloudWatch CloudWatchAPI
	STS        STSAPI
}

type AWSClientFactory interface {
	ResolveTargets(context.Context, *PluginConfig) ([]ResolvedTarget, error)
	ClientsForTarget(context.Context, ResolvedTarget) (AWSClientSet, error)
}

type SDKClientFactory struct{}

type ResolvedTarget struct {
	Account AccountContext
	Region  string
	Config  aws.Config
}

type Collector struct {
	Logger  hclog.Logger
	Config  *PluginConfig
	Factory AWSClientFactory
	Now     func() time.Time
}

type CollectionResult struct {
	Records []*ResourceRecord
	Err     error
}

func (f *SDKClientFactory) ResolveTargets(ctx context.Context, cfg *PluginConfig) ([]ResolvedTarget, error) {
	baseCfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("load AWS SDK config: %w", err)
	}
	if err := cfg.validateResolvedDefaults(baseCfg.Region); err != nil {
		return nil, err
	}

	accounts := effectiveAccounts(cfg)

	var targets []ResolvedTarget
	var accumulated error
	for _, account := range accounts {
		regions := effectiveRegions(account, cfg, baseCfg.Region)
		if len(regions) == 0 {
			accumulated = errors.Join(accumulated, fmt.Errorf("account %q has no configured regions and AWS SDK default region is empty", account.AccountID))
			continue
		}

		for _, region := range regions {
			targetCfg := baseCfg.Copy()
			targetCfg.Region = region
			if account.RoleARN != "" {
				stsClient := sts.NewFromConfig(assumeRoleSourceConfig(baseCfg, region))
				provider := stscreds.NewAssumeRoleProvider(stsClient, account.RoleARN, func(options *stscreds.AssumeRoleOptions) {
					if account.ExternalID != "" {
						options.ExternalID = aws.String(account.ExternalID)
					}
					if account.SessionName != "" {
						options.RoleSessionName = account.SessionName
					}
				})
				targetCfg.Credentials = aws.NewCredentialsCache(provider)
			}
			stsClient := sts.NewFromConfig(targetCfg)
			identity, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
			actualAccountID := account.AccountID
			if err != nil {
				accumulated = errors.Join(accumulated, fmt.Errorf("resolve caller identity for account %q region %q: %w", account.AccountID, region, err))
			} else if actualAccountID == "" {
				actualAccountID = aws.ToString(identity.Account)
			}
			targets = append(targets, ResolvedTarget{
				Account: AccountContext{
					AccountID: actualAccountID,
					RoleARN:   account.RoleARN,
					Tags:      account.Tags,
				},
				Region: region,
				Config: targetCfg,
			})
		}
	}
	return targets, accumulated
}

func assumeRoleSourceConfig(baseCfg aws.Config, region string) aws.Config {
	sourceCfg := baseCfg.Copy()
	sourceCfg.Region = region
	return sourceCfg
}

func effectiveAccounts(cfg *PluginConfig) []AccountConfig {
	if len(cfg.Accounts) == 0 {
		return []AccountConfig{{}}
	}
	return cfg.Accounts
}

func effectiveRegions(account AccountConfig, cfg *PluginConfig, sdkDefaultRegion string) []string {
	regions := account.Regions
	if len(regions) == 0 {
		regions = cfg.DefaultRegions
	}
	if len(regions) == 0 && strings.TrimSpace(sdkDefaultRegion) != "" {
		regions = []string{strings.TrimSpace(sdkDefaultRegion)}
	}
	return cleanStringList(regions)
}

func (f *SDKClientFactory) ClientsForTarget(ctx context.Context, target ResolvedTarget) (AWSClientSet, error) {
	return AWSClientSet{
		RDS:        rds.NewFromConfig(target.Config),
		CloudTrail: cloudtrail.NewFromConfig(target.Config),
		CloudWatch: cloudwatch.NewFromConfig(target.Config),
		STS:        sts.NewFromConfig(target.Config),
	}, nil
}

func (c *Collector) Collect(ctx context.Context) CollectionResult {
	factory := c.Factory
	if factory == nil {
		factory = &SDKClientFactory{}
	}
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	collectedAt := now()
	windowStart, windowEnd := c.Config.lookbackWindow(collectedAt)
	window := Window{Start: windowStart.Format(time.RFC3339), End: windowEnd.Format(time.RFC3339)}

	targets, err := factory.ResolveTargets(ctx, c.Config)
	var accumulated error
	if err != nil {
		accumulated = errors.Join(accumulated, err)
	}
	if len(targets) == 0 {
		return CollectionResult{Err: errors.Join(accumulated, errors.New("no AWS account/region targets resolved"))}
	}

	workerCount := c.Config.MaxConcurrency
	if workerCount > len(targets) {
		workerCount = len(targets)
	}
	jobs := make(chan ResolvedTarget)
	results := make(chan CollectionResult, len(targets))
	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range jobs {
				targetCtx, cancel := context.WithTimeout(ctx, time.Duration(c.Config.APITimeoutSeconds)*time.Second)
				results <- c.collectTarget(targetCtx, factory, target, collectedAt, window, windowStart, windowEnd)
				cancel()
			}
		}()
	}
	for _, target := range targets {
		jobs <- target
	}
	close(jobs)
	wg.Wait()
	close(results)

	records := make([]*ResourceRecord, 0)
	for result := range results {
		records = append(records, result.Records...)
		accumulated = errors.Join(accumulated, result.Err)
	}
	return CollectionResult{Records: records, Err: accumulated}
}

func (c *Collector) collectTarget(ctx context.Context, factory AWSClientFactory, target ResolvedTarget, collectedAt time.Time, window Window, windowStart time.Time, windowEnd time.Time) CollectionResult {
	clients, err := factory.ClientsForTarget(ctx, target)
	if err != nil {
		return CollectionResult{Err: fmt.Errorf("create AWS clients for account %q region %q: %w", target.Account.AccountID, target.Region, err)}
	}
	var accumulated error
	if target.Account.AccountID == "" && clients.STS != nil {
		if identity, idErr := clients.STS.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}); idErr == nil {
			target.Account.AccountID = aws.ToString(identity.Account)
		} else {
			accumulated = errors.Join(accumulated, fmt.Errorf("resolve caller identity for region %q: %w", target.Region, idErr))
		}
	}

	var records []*ResourceRecord
	instances, instanceErrors := c.collectInstances(ctx, clients.RDS)
	accumulated = joinCollectionErrors(accumulated, instanceErrors)
	clusters, clusterErrors := c.collectClusters(ctx, clients.RDS)
	accumulated = joinCollectionErrors(accumulated, clusterErrors)

	instanceSnapshots, instanceSnapshotRecords, snapErr := c.collectDBSnapshots(ctx, clients.RDS, target, collectedAt)
	accumulated = errors.Join(accumulated, snapErr)
	clusterSnapshots, clusterSnapshotRecords, clusterSnapErr := c.collectClusterSnapshots(ctx, clients.RDS, target, collectedAt)
	accumulated = errors.Join(accumulated, clusterSnapErr)
	records = append(records, instanceSnapshotRecords...)
	records = append(records, clusterSnapshotRecords...)

	cloudTrailEvents, cloudTrailErr := c.collectCloudTrailEvents(ctx, clients.CloudTrail, windowStart, windowEnd)
	accumulated = errors.Join(accumulated, cloudTrailErr)
	commonResourceErrors := errorsFor(cloudTrailErr, "cloudtrail_events")

	for _, instance := range instances {
		resourceErrors := append([]CollectionError{}, instanceErrors...)
		resourceErrors = append(resourceErrors, commonResourceErrors...)
		tags, tagErr := c.collectTags(ctx, clients.RDS, aws.ToString(instance.DBInstanceArn), "instance tags")
		if tagErr != nil {
			resourceErrors = append(resourceErrors, CollectionError{Scope: "tags", Message: tagErr.Error()})
			accumulated = errors.Join(accumulated, tagErr)
		}
		sslEnforcement := collectInstanceSSLEnforcement(ctx, clients.RDS, instance, &resourceErrors, &accumulated)
		dynamic := c.dynamicForResource(ctx, clients, aws.ToString(instance.DBInstanceIdentifier), aws.ToString(instance.DBInstanceArn), rdstypes.SourceTypeDbInstance, "DBInstanceIdentifier", windowStart, windowEnd, cloudTrailEvents, &resourceErrors, &accumulated)
		record := newInstanceRecord(target.Account, target.Region, instance, tags, instanceSnapshots[aws.ToString(instance.DBInstanceIdentifier)], dynamic, sslEnforcement, resourceErrors, c.Config.PolicyInputs, collectedAt, window)
		records = append(records, &record)
	}

	for _, cluster := range clusters {
		resourceErrors := append([]CollectionError{}, clusterErrors...)
		resourceErrors = append(resourceErrors, commonResourceErrors...)
		tags, tagErr := c.collectTags(ctx, clients.RDS, aws.ToString(cluster.DBClusterArn), "cluster tags")
		if tagErr != nil {
			resourceErrors = append(resourceErrors, CollectionError{Scope: "tags", Message: tagErr.Error()})
			accumulated = errors.Join(accumulated, tagErr)
		}
		sslEnforcement := collectClusterSSLEnforcement(ctx, clients.RDS, cluster, &resourceErrors, &accumulated)
		dynamic := c.dynamicForResource(ctx, clients, aws.ToString(cluster.DBClusterIdentifier), aws.ToString(cluster.DBClusterArn), rdstypes.SourceTypeDbCluster, "DBClusterIdentifier", windowStart, windowEnd, cloudTrailEvents, &resourceErrors, &accumulated)
		record := newClusterRecord(target.Account, target.Region, cluster, tags, clusterSnapshots[aws.ToString(cluster.DBClusterIdentifier)], dynamic, sslEnforcement, resourceErrors, c.Config.PolicyInputs, collectedAt, window)
		records = append(records, &record)
	}

	return CollectionResult{Records: records, Err: accumulated}
}

func (c *Collector) collectInstances(ctx context.Context, client RDSAPI) ([]rdstypes.DBInstance, []CollectionError) {
	var marker *string
	var instances []rdstypes.DBInstance
	var errs []CollectionError
	for {
		out, err := client.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{Marker: marker})
		if err != nil {
			errs = append(errs, CollectionError{Scope: "describe_db_instances", Message: err.Error()})
			return instances, errs
		}
		instances = append(instances, out.DBInstances...)
		if out.Marker == nil || aws.ToString(out.Marker) == "" {
			return instances, errs
		}
		marker = out.Marker
	}
}

func (c *Collector) collectClusters(ctx context.Context, client RDSAPI) ([]rdstypes.DBCluster, []CollectionError) {
	var marker *string
	var clusters []rdstypes.DBCluster
	var errs []CollectionError
	for {
		out, err := client.DescribeDBClusters(ctx, &rds.DescribeDBClustersInput{Marker: marker})
		if err != nil {
			errs = append(errs, CollectionError{Scope: "describe_db_clusters", Message: err.Error()})
			return clusters, errs
		}
		clusters = append(clusters, out.DBClusters...)
		if out.Marker == nil || aws.ToString(out.Marker) == "" {
			return clusters, errs
		}
		marker = out.Marker
	}
}

func (c *Collector) collectDBSnapshots(ctx context.Context, client RDSAPI, target ResolvedTarget, collectedAt time.Time) (map[string][]map[string]interface{}, []*ResourceRecord, error) {
	var accumulated error
	var marker *string
	grouped := map[string][]map[string]interface{}{}
	var records []*ResourceRecord
	for {
		out, err := client.DescribeDBSnapshots(ctx, &rds.DescribeDBSnapshotsInput{Marker: marker})
		if err != nil {
			return grouped, records, fmt.Errorf("describe_db_snapshots: %w", err)
		}
		for _, snapshot := range out.DBSnapshots {
			attrs, attrErr := c.collectDBSnapshotAttributesIfManual(ctx, client, snapshot)
			if attrErr != nil {
				accumulated = errors.Join(accumulated, attrErr)
			}
			tags, tagErr := c.collectTags(ctx, client, aws.ToString(snapshot.DBSnapshotArn), "snapshot tags")
			if tagErr != nil {
				accumulated = errors.Join(accumulated, tagErr)
			}
			snapMap := dbSnapshotToMap(snapshot, attrs)
			sourceID := aws.ToString(snapshot.DBInstanceIdentifier)
			grouped[sourceID] = append(grouped[sourceID], snapMap)
			resource := ResourceIdentity{
				ID:     aws.ToString(snapshot.DBSnapshotIdentifier),
				ARN:    aws.ToString(snapshot.DBSnapshotArn),
				Type:   "db-snapshot",
				Engine: aws.ToString(snapshot.Engine),
			}
			recordErrors := errorsFor(attrErr, "snapshot_attributes")
			recordErrors = append(recordErrors, errorsFor(tagErr, "snapshot_tags")...)
			record := newSnapshotRecord(target.Account, target.Region, resource, snapMap, tags, recordErrors, c.Config.PolicyInputs, collectedAt, snapshot)
			records = append(records, &record)
		}
		if out.Marker == nil || aws.ToString(out.Marker) == "" {
			return grouped, records, accumulated
		}
		marker = out.Marker
	}
}

func (c *Collector) collectClusterSnapshots(ctx context.Context, client RDSAPI, target ResolvedTarget, collectedAt time.Time) (map[string][]map[string]interface{}, []*ResourceRecord, error) {
	var accumulated error
	var marker *string
	grouped := map[string][]map[string]interface{}{}
	var records []*ResourceRecord
	for {
		out, err := client.DescribeDBClusterSnapshots(ctx, &rds.DescribeDBClusterSnapshotsInput{Marker: marker})
		if err != nil {
			return grouped, records, fmt.Errorf("describe_db_cluster_snapshots: %w", err)
		}
		for _, snapshot := range out.DBClusterSnapshots {
			attrs, attrErr := c.collectDBClusterSnapshotAttributesIfManual(ctx, client, snapshot)
			if attrErr != nil {
				accumulated = errors.Join(accumulated, attrErr)
			}
			tags, tagErr := c.collectTags(ctx, client, aws.ToString(snapshot.DBClusterSnapshotArn), "cluster snapshot tags")
			if tagErr != nil {
				accumulated = errors.Join(accumulated, tagErr)
			}
			snapMap := dbClusterSnapshotToMap(snapshot, attrs)
			sourceID := aws.ToString(snapshot.DBClusterIdentifier)
			grouped[sourceID] = append(grouped[sourceID], snapMap)
			resource := ResourceIdentity{
				ID:     aws.ToString(snapshot.DBClusterSnapshotIdentifier),
				ARN:    aws.ToString(snapshot.DBClusterSnapshotArn),
				Type:   "db-cluster-snapshot",
				Engine: aws.ToString(snapshot.Engine),
			}
			recordErrors := errorsFor(attrErr, "cluster_snapshot_attributes")
			recordErrors = append(recordErrors, errorsFor(tagErr, "cluster_snapshot_tags")...)
			record := newSnapshotRecord(target.Account, target.Region, resource, snapMap, tags, recordErrors, c.Config.PolicyInputs, collectedAt, snapshot)
			records = append(records, &record)
		}
		if out.Marker == nil || aws.ToString(out.Marker) == "" {
			return grouped, records, accumulated
		}
		marker = out.Marker
	}
}

func (c *Collector) collectDBSnapshotAttributesIfManual(ctx context.Context, client RDSAPI, snapshot rdstypes.DBSnapshot) ([]rdstypes.DBSnapshotAttribute, error) {
	if !isManualSnapshotType(aws.ToString(snapshot.SnapshotType)) {
		return nil, nil
	}
	id := aws.ToString(snapshot.DBSnapshotIdentifier)
	out, err := client.DescribeDBSnapshotAttributes(ctx, &rds.DescribeDBSnapshotAttributesInput{DBSnapshotIdentifier: aws.String(id)})
	if err != nil {
		return nil, fmt.Errorf("describe_db_snapshot_attributes %q: %w", id, err)
	}
	if out.DBSnapshotAttributesResult == nil {
		return nil, nil
	}
	return out.DBSnapshotAttributesResult.DBSnapshotAttributes, nil
}

func (c *Collector) collectDBClusterSnapshotAttributesIfManual(ctx context.Context, client RDSAPI, snapshot rdstypes.DBClusterSnapshot) ([]rdstypes.DBClusterSnapshotAttribute, error) {
	if !isManualSnapshotType(aws.ToString(snapshot.SnapshotType)) {
		return nil, nil
	}
	id := aws.ToString(snapshot.DBClusterSnapshotIdentifier)
	out, err := client.DescribeDBClusterSnapshotAttributes(ctx, &rds.DescribeDBClusterSnapshotAttributesInput{DBClusterSnapshotIdentifier: aws.String(id)})
	if err != nil {
		return nil, fmt.Errorf("describe_db_cluster_snapshot_attributes %q: %w", id, err)
	}
	if out.DBClusterSnapshotAttributesResult == nil {
		return nil, nil
	}
	return out.DBClusterSnapshotAttributesResult.DBClusterSnapshotAttributes, nil
}

func isManualSnapshotType(snapshotType string) bool {
	return strings.EqualFold(snapshotType, "manual")
}

func (c *Collector) collectTags(ctx context.Context, client RDSAPI, arn string, scope string) (map[string]string, error) {
	if arn == "" {
		return map[string]string{}, nil
	}
	out, err := client.ListTagsForResource(ctx, &rds.ListTagsForResourceInput{ResourceName: aws.String(arn)})
	if err != nil {
		return map[string]string{}, fmt.Errorf("%s: %w", scope, err)
	}
	tags := make(map[string]string, len(out.TagList))
	for _, tag := range out.TagList {
		tags[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
	}
	return tags, nil
}

func collectInstanceSSLEnforcement(ctx context.Context, client RDSAPI, instance rdstypes.DBInstance, resourceErrors *[]CollectionError, accumulated *error) map[string]string {
	ssl := map[string]string{}
	for _, group := range instance.DBParameterGroups {
		name := aws.ToString(group.DBParameterGroupName)
		if name == "" {
			continue
		}
		value, err := collectDBSSLEnforcement(ctx, client, name)
		if err != nil {
			*resourceErrors = append(*resourceErrors, CollectionError{Scope: "db_parameter_require_ssl", Message: err.Error()})
			*accumulated = errors.Join(*accumulated, err)
			continue
		}
		ssl[name] = value
	}
	return ssl
}

func collectClusterSSLEnforcement(ctx context.Context, client RDSAPI, cluster rdstypes.DBCluster, resourceErrors *[]CollectionError, accumulated *error) map[string]string {
	ssl := map[string]string{}
	group := aws.ToString(cluster.DBClusterParameterGroup)
	if group == "" {
		return ssl
	}
	value, err := collectClusterSSLEnforcementValue(ctx, client, group)
	if err != nil {
		*resourceErrors = append(*resourceErrors, CollectionError{Scope: "db_cluster_parameter_require_ssl", Message: err.Error()})
		*accumulated = errors.Join(*accumulated, err)
		return ssl
	}
	ssl[group] = value
	return ssl
}

var sslEnforcementParameterNames = []string{"rds.force_ssl", "require_ssl"}

func collectDBSSLEnforcement(ctx context.Context, client RDSAPI, groupName string) (string, error) {
	var marker *string
	for {
		out, err := client.DescribeDBParameters(ctx, &rds.DescribeDBParametersInput{
			DBParameterGroupName: aws.String(groupName),
			Marker:               marker,
		})
		if err != nil {
			return "", fmt.Errorf("describe_db_parameters %q: %w", groupName, err)
		}
		for _, parameter := range out.Parameters {
			if isSSLEnforcementParameter(aws.ToString(parameter.ParameterName)) {
				return aws.ToString(parameter.ParameterValue), nil
			}
		}
		if out.Marker == nil || aws.ToString(out.Marker) == "" {
			return "", nil
		}
		marker = out.Marker
	}
}

func collectClusterSSLEnforcementValue(ctx context.Context, client RDSAPI, groupName string) (string, error) {
	var marker *string
	for {
		out, err := client.DescribeDBClusterParameters(ctx, &rds.DescribeDBClusterParametersInput{
			DBClusterParameterGroupName: aws.String(groupName),
			Marker:                      marker,
		})
		if err != nil {
			return "", fmt.Errorf("describe_db_cluster_parameters %q: %w", groupName, err)
		}
		for _, parameter := range out.Parameters {
			if isSSLEnforcementParameter(aws.ToString(parameter.ParameterName)) {
				return aws.ToString(parameter.ParameterValue), nil
			}
		}
		if out.Marker == nil || aws.ToString(out.Marker) == "" {
			return "", nil
		}
		marker = out.Marker
	}
}

func isSSLEnforcementParameter(name string) bool {
	for _, candidate := range sslEnforcementParameterNames {
		if strings.EqualFold(name, candidate) {
			return true
		}
	}
	return false
}

func (c *Collector) collectCloudTrailEvents(ctx context.Context, client CloudTrailAPI, start time.Time, end time.Time) ([]map[string]interface{}, error) {
	if client == nil {
		return nil, nil
	}
	eventNamesBySource := map[string]map[string]struct{}{
		"rds.amazonaws.com": {
			"ModifyDBInstance":                 {},
			"ModifyDBCluster":                  {},
			"ModifyDBParameterGroup":           {},
			"ModifyDBClusterParameterGroup":    {},
			"CreateDBInstance":                 {},
			"CreateDBCluster":                  {},
			"DeleteDBInstance":                 {},
			"DeleteDBCluster":                  {},
			"DeleteDBSnapshot":                 {},
			"DeleteDBClusterSnapshot":          {},
			"ModifyDBSnapshotAttribute":        {},
			"ModifyDBClusterSnapshotAttribute": {},
			"RevokeDBSecurityGroupIngress":     {},
		},
		"iam.amazonaws.com": {
			"DeleteUser":       {},
			"DetachRolePolicy": {},
		},
	}
	var accumulated error
	events := make([]map[string]interface{}, 0)
	for eventSource, allowedEventNames := range eventNamesBySource {
		var token *string
		for {
			out, err := client.LookupEvents(ctx, &cloudtrail.LookupEventsInput{
				StartTime: aws.Time(start),
				EndTime:   aws.Time(end),
				LookupAttributes: []cloudtrailtypes.LookupAttribute{
					{
						AttributeKey:   cloudtrailtypes.LookupAttributeKeyEventSource,
						AttributeValue: aws.String(eventSource),
					},
				},
				NextToken:  token,
				MaxResults: aws.Int32(50),
			})
			if err != nil {
				accumulated = errors.Join(accumulated, fmt.Errorf("cloudtrail lookup %s: %w", eventSource, err))
				break
			}
			for _, event := range out.Events {
				if _, ok := allowedEventNames[aws.ToString(event.EventName)]; ok {
					events = append(events, eventToMap(event))
				}
			}
			if out.NextToken == nil || aws.ToString(out.NextToken) == "" {
				break
			}
			token = out.NextToken
		}
	}
	return events, accumulated
}

func (c *Collector) dynamicForResource(ctx context.Context, clients AWSClientSet, sourceID string, sourceARN string, sourceType rdstypes.SourceType, metricDimension string, start time.Time, end time.Time, cloudTrailEvents []map[string]interface{}, resourceErrors *[]CollectionError, accumulated *error) map[string]interface{} {
	rdsEvents, err := c.collectRDSEvents(ctx, clients.RDS, sourceID, sourceType, start, end)
	if err != nil {
		*resourceErrors = append(*resourceErrors, CollectionError{Scope: "rds_events", Message: err.Error()})
		*accumulated = errors.Join(*accumulated, err)
	}
	metrics, metricErr := c.collectCloudWatchMetrics(ctx, clients.CloudWatch, sourceID, metricDimension, start, end)
	if metricErr != nil {
		*resourceErrors = append(*resourceErrors, CollectionError{Scope: "cloudwatch_metrics", Message: metricErr.Error()})
		*accumulated = errors.Join(*accumulated, metricErr)
	}
	resourceCloudTrailEvents, accountCloudTrailEvents := splitCloudTrailEventsForResource(cloudTrailEvents, sourceID, sourceARN)
	return map[string]interface{}{
		"cloudtrail_events":         resourceCloudTrailEvents,
		"account_cloudtrail_events": accountCloudTrailEvents,
		"rds_events":                rdsEvents,
		"cloudwatch_metrics":        metrics,
	}
}

func splitCloudTrailEventsForResource(events []map[string]interface{}, sourceID string, sourceARN string) ([]map[string]interface{}, []map[string]interface{}) {
	resourceEvents := make([]map[string]interface{}, 0)
	accountEvents := make([]map[string]interface{}, 0)
	for _, event := range events {
		if cloudTrailEventMatchesResource(event, sourceID, sourceARN) {
			resourceEvents = append(resourceEvents, event)
			continue
		}
		accountEvents = append(accountEvents, event)
	}
	return resourceEvents, accountEvents
}

func cloudTrailEventMatchesResource(event map[string]interface{}, sourceID string, sourceARN string) bool {
	if sourceID == "" && sourceARN == "" {
		return false
	}
	if resources, ok := event["resources"]; ok && cloudTrailResourcesMatch(resources, sourceID, sourceARN) {
		return true
	}
	if raw, ok := event["cloudtrail_event"].(string); ok && raw != "" {
		return cloudTrailPayloadContainsResource(raw, sourceID, sourceARN)
	}
	return false
}

func cloudTrailResourcesMatch(resources interface{}, sourceID string, sourceARN string) bool {
	switch typed := resources.(type) {
	case []cloudtrailtypes.Resource:
		for _, resource := range typed {
			if stringMatchesResource(aws.ToString(resource.ResourceName), sourceID, sourceARN) {
				return true
			}
		}
	case []interface{}:
		for _, item := range typed {
			if resourceMapMatches(item, sourceID, sourceARN) {
				return true
			}
		}
	}
	return false
}

func resourceMapMatches(item interface{}, sourceID string, sourceARN string) bool {
	resource, ok := item.(map[string]interface{})
	if !ok {
		return false
	}
	for _, key := range []string{"ResourceName", "resourceName", "resource_arn", "resourceArn", "ARN", "arn"} {
		if value, ok := resource[key].(string); ok && stringMatchesResource(value, sourceID, sourceARN) {
			return true
		}
	}
	return false
}

func cloudTrailPayloadContainsResource(raw string, sourceID string, sourceARN string) bool {
	var payload interface{}
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return stringMatchesResource(raw, sourceID, sourceARN)
	}
	return jsonValueContainsResource(payload, sourceID, sourceARN)
}

func jsonValueContainsResource(value interface{}, sourceID string, sourceARN string) bool {
	switch typed := value.(type) {
	case string:
		return stringMatchesResource(typed, sourceID, sourceARN)
	case []interface{}:
		for _, item := range typed {
			if jsonValueContainsResource(item, sourceID, sourceARN) {
				return true
			}
		}
	case map[string]interface{}:
		for _, item := range typed {
			if jsonValueContainsResource(item, sourceID, sourceARN) {
				return true
			}
		}
	}
	return false
}

func stringMatchesResource(value string, sourceID string, sourceARN string) bool {
	if sourceID != "" && value == sourceID {
		return true
	}
	if sourceARN != "" && value == sourceARN {
		return true
	}
	return false
}

func (c *Collector) collectRDSEvents(ctx context.Context, client RDSAPI, sourceID string, sourceType rdstypes.SourceType, start time.Time, end time.Time) ([]map[string]interface{}, error) {
	var marker *string
	events := make([]map[string]interface{}, 0)
	for {
		out, err := client.DescribeEvents(ctx, &rds.DescribeEventsInput{
			SourceIdentifier: aws.String(sourceID),
			SourceType:       sourceType,
			EventCategories:  []string{"backup", "restoration", "deletion"},
			StartTime:        aws.Time(start),
			EndTime:          aws.Time(end),
			Marker:           marker,
		})
		if err != nil {
			return events, fmt.Errorf("describe_events %q: %w", sourceID, err)
		}
		for _, event := range out.Events {
			events = append(events, map[string]interface{}{
				"source_identifier": aws.ToString(event.SourceIdentifier),
				"source_type":       string(event.SourceType),
				"event_categories":  event.EventCategories,
				"message":           aws.ToString(event.Message),
				"date":              formatTime(event.Date),
				"source_arn":        aws.ToString(event.SourceArn),
			})
		}
		if out.Marker == nil || aws.ToString(out.Marker) == "" {
			return events, nil
		}
		marker = out.Marker
	}
}

func (c *Collector) collectCloudWatchMetrics(ctx context.Context, client CloudWatchAPI, resourceID string, dimensionName string, start time.Time, end time.Time) (map[string]interface{}, error) {
	if client == nil || resourceID == "" {
		return map[string]interface{}{}, nil
	}
	period := int32(3600)
	metrics := []string{"CPUUtilization", "DatabaseConnections", "FreeStorageSpace"}
	queries := make([]cloudwatchtypes.MetricDataQuery, 0, len(metrics)*3)
	for _, metricName := range metrics {
		idBase := strings.ToLower(metricName)
		idBase = strings.ReplaceAll(idBase, "utilization", "util")
		queries = append(queries,
			metricQuery(idBase+"avg", metricName, dimensionName, resourceID, "Average", period),
			metricQuery(idBase+"max", metricName, dimensionName, resourceID, "Maximum", period),
			metricQuery(idBase+"p99", metricName, dimensionName, resourceID, "p99", period),
		)
	}
	out, err := client.GetMetricData(ctx, &cloudwatch.GetMetricDataInput{
		StartTime:         aws.Time(start),
		EndTime:           aws.Time(end),
		MetricDataQueries: queries,
	})
	if err != nil {
		return nil, fmt.Errorf("get_metric_data %q: %w", resourceID, err)
	}
	result := map[string]interface{}{}
	for _, metric := range out.MetricDataResults {
		values := metric.Values
		result[aws.ToString(metric.Id)] = map[string]interface{}{
			"label":      aws.ToString(metric.Label),
			"status":     string(metric.StatusCode),
			"timestamps": metric.Timestamps,
			"values":     values,
		}
	}
	return result, nil
}

func metricQuery(id string, metricName string, dimensionName string, dimensionValue string, stat string, period int32) cloudwatchtypes.MetricDataQuery {
	return cloudwatchtypes.MetricDataQuery{
		Id:         aws.String(id),
		ReturnData: aws.Bool(true),
		MetricStat: &cloudwatchtypes.MetricStat{
			Period: aws.Int32(period),
			Stat:   aws.String(stat),
			Metric: &cloudwatchtypes.Metric{
				Namespace:  aws.String("AWS/RDS"),
				MetricName: aws.String(metricName),
				Dimensions: []cloudwatchtypes.Dimension{
					{
						Name:  aws.String(dimensionName),
						Value: aws.String(dimensionValue),
					},
				},
			},
		},
	}
}

func dbSnapshotToMap(snapshot rdstypes.DBSnapshot, attrs []rdstypes.DBSnapshotAttribute) map[string]interface{} {
	return map[string]interface{}{
		"snapshot_identifier":  aws.ToString(snapshot.DBSnapshotIdentifier),
		"snapshot_arn":         aws.ToString(snapshot.DBSnapshotArn),
		"source_identifier":    aws.ToString(snapshot.DBInstanceIdentifier),
		"snapshot_type":        aws.ToString(snapshot.SnapshotType),
		"status":               aws.ToString(snapshot.Status),
		"encrypted":            aws.ToBool(snapshot.Encrypted),
		"kms_key_id":           aws.ToString(snapshot.KmsKeyId),
		"snapshot_create_time": formatTime(snapshot.SnapshotCreateTime),
		"engine":               aws.ToString(snapshot.Engine),
		"shared_accounts":      snapshotSharedAccounts(attrs),
		"public":               snapshotPublic(attrs),
	}
}

func dbClusterSnapshotToMap(snapshot rdstypes.DBClusterSnapshot, attrs []rdstypes.DBClusterSnapshotAttribute) map[string]interface{} {
	return map[string]interface{}{
		"snapshot_identifier":  aws.ToString(snapshot.DBClusterSnapshotIdentifier),
		"snapshot_arn":         aws.ToString(snapshot.DBClusterSnapshotArn),
		"source_identifier":    aws.ToString(snapshot.DBClusterIdentifier),
		"snapshot_type":        aws.ToString(snapshot.SnapshotType),
		"status":               aws.ToString(snapshot.Status),
		"encrypted":            aws.ToBool(snapshot.StorageEncrypted),
		"kms_key_id":           aws.ToString(snapshot.KmsKeyId),
		"snapshot_create_time": formatTime(snapshot.SnapshotCreateTime),
		"engine":               aws.ToString(snapshot.Engine),
		"shared_accounts":      clusterSnapshotSharedAccounts(attrs),
		"public":               clusterSnapshotPublic(attrs),
	}
}

func snapshotSharedAccounts(attrs []rdstypes.DBSnapshotAttribute) []string {
	accounts := []string{}
	for _, attr := range attrs {
		if aws.ToString(attr.AttributeName) == "restore" {
			for _, value := range attr.AttributeValues {
				if value != "all" {
					accounts = append(accounts, value)
				}
			}
		}
	}
	return accounts
}

func snapshotPublic(attrs []rdstypes.DBSnapshotAttribute) bool {
	for _, attr := range attrs {
		if aws.ToString(attr.AttributeName) == "restore" {
			for _, value := range attr.AttributeValues {
				if value == "all" {
					return true
				}
			}
		}
	}
	return false
}

func clusterSnapshotSharedAccounts(attrs []rdstypes.DBClusterSnapshotAttribute) []string {
	accounts := []string{}
	for _, attr := range attrs {
		if aws.ToString(attr.AttributeName) == "restore" {
			for _, value := range attr.AttributeValues {
				if value != "all" {
					accounts = append(accounts, value)
				}
			}
		}
	}
	return accounts
}

func clusterSnapshotPublic(attrs []rdstypes.DBClusterSnapshotAttribute) bool {
	for _, attr := range attrs {
		if aws.ToString(attr.AttributeName) == "restore" {
			for _, value := range attr.AttributeValues {
				if value == "all" {
					return true
				}
			}
		}
	}
	return false
}

func errorsFromCollection(collectionErrors []CollectionError) []error {
	errs := make([]error, 0, len(collectionErrors))
	for _, item := range collectionErrors {
		errs = append(errs, fmt.Errorf("%s: %s", item.Scope, item.Message))
	}
	return errs
}

func joinCollectionErrors(base error, collectionErrors []CollectionError) error {
	errs := []error{base}
	errs = append(errs, errorsFromCollection(collectionErrors)...)
	return errors.Join(errs...)
}

func errorsFor(err error, scope string) []CollectionError {
	if err == nil {
		return nil
	}
	return []CollectionError{{Scope: scope, Message: err.Error()}}
}
