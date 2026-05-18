package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/compliance-framework/plugin-aws-rds-aurora-psql/internal"
)

const (
	sourceName      = "aws-rds-aurora-psql"
	schemaVersionV1 = "v1"
)

type AccountContext struct {
	AccountID string            `json:"account_id"`
	RoleARN   string            `json:"role_arn,omitempty"`
	Tags      map[string]string `json:"tags,omitempty"`
}

type RegionContext struct {
	Name string `json:"name"`
}

type ResourceIdentity struct {
	ID            string `json:"id"`
	ARN           string `json:"arn"`
	Type          string `json:"type"`
	Engine        string `json:"engine,omitempty"`
	EngineVersion string `json:"engine_version,omitempty"`
}

type CollectionMetadata struct {
	CollectedAt      string            `json:"collected_at"`
	CollectorVersion string            `json:"collector_version"`
	CollectionType   string            `json:"collection_type"`
	Errors           []CollectionError `json:"errors"`
	RawPayloadHashes map[string]string `json:"raw_payload_hashes,omitempty"`
	LookbackWindow   *Window           `json:"lookback_window,omitempty"`
}

type Window struct {
	Start string `json:"start"`
	End   string `json:"end"`
}

type CollectionError struct {
	Scope   string `json:"scope"`
	Message string `json:"message"`
}

type NormalizedInput struct {
	SchemaVersion string                   `json:"schema_version"`
	Source        string                   `json:"source"`
	Account       AccountContext           `json:"account"`
	Region        RegionContext            `json:"region"`
	Resource      ResourceIdentity         `json:"resource"`
	Config        map[string]interface{}   `json:"config"`
	Dynamic       map[string]interface{}   `json:"dynamic"`
	Snapshots     []map[string]interface{} `json:"snapshots"`
	Tags          map[string]string        `json:"tags"`
	Collection    CollectionMetadata       `json:"collection"`
	PolicyInputs  map[string]interface{}   `json:"policy_inputs"`
}

type ResourceRecord struct {
	Input         NormalizedInput
	Labels        map[string]string
	SubjectID     string
	SubjectType   proto.SubjectType
	InventoryType string
	Title         string
	Description   string
	Raw           interface{}
}

func newInstanceRecord(account AccountContext, region string, instance rdstypes.DBInstance, tags map[string]string, snapshots []map[string]interface{}, dynamic map[string]interface{}, sslEnforcement map[string]string, errors []CollectionError, policyInputs map[string]interface{}, collectedAt time.Time, window Window) ResourceRecord {
	id := aws.ToString(instance.DBInstanceIdentifier)
	arn := aws.ToString(instance.DBInstanceArn)
	resource := ResourceIdentity{
		ID:            id,
		ARN:           arn,
		Type:          "db-instance",
		Engine:        aws.ToString(instance.Engine),
		EngineVersion: aws.ToString(instance.EngineVersion),
	}
	config := map[string]interface{}{
		"db_instance_identifier":                     id,
		"db_instance_arn":                            arn,
		"db_instance_class":                          aws.ToString(instance.DBInstanceClass),
		"engine":                                     aws.ToString(instance.Engine),
		"engine_version":                             aws.ToString(instance.EngineVersion),
		"storage_encrypted":                          aws.ToBool(instance.StorageEncrypted),
		"kms_key_id":                                 aws.ToString(instance.KmsKeyId),
		"multi_az":                                   aws.ToBool(instance.MultiAZ),
		"availability_zone":                          aws.ToString(instance.AvailabilityZone),
		"secondary_availability_zone":                aws.ToString(instance.SecondaryAvailabilityZone),
		"backup_retention_period":                    aws.ToInt32(instance.BackupRetentionPeriod),
		"preferred_backup_window":                    aws.ToString(instance.PreferredBackupWindow),
		"latest_restorable_time":                     formatTime(instance.LatestRestorableTime),
		"deletion_protection":                        aws.ToBool(instance.DeletionProtection),
		"publicly_accessible":                        aws.ToBool(instance.PubliclyAccessible),
		"iam_database_authentication_enabled":        aws.ToBool(instance.IAMDatabaseAuthenticationEnabled),
		"ca_certificate_identifier":                  aws.ToString(instance.CACertificateIdentifier),
		"enabled_cloudwatch_logs_exports":            stringSliceOrEmpty(instance.EnabledCloudwatchLogsExports),
		"monitoring_interval":                        aws.ToInt32(instance.MonitoringInterval),
		"monitoring_role_arn":                        aws.ToString(instance.MonitoringRoleArn),
		"enhanced_monitoring_resource_arn":           aws.ToString(instance.EnhancedMonitoringResourceArn),
		"db_parameter_groups":                        instance.DBParameterGroups,
		"ssl_enforcement":                            sslEnforcement,
		"db_subnet_group":                            instance.DBSubnetGroup,
		"vpc_security_groups":                        instance.VpcSecurityGroups,
		"read_replica_source_db_instance_identifier": aws.ToString(instance.ReadReplicaSourceDBInstanceIdentifier),
		"read_replica_db_instance_identifiers":       instance.ReadReplicaDBInstanceIdentifiers,
	}
	return newResourceRecord(account, region, resource, config, tags, snapshots, dynamic, errors, policyInputs, collectedAt, window, instance, "aws-rds-instance", fmt.Sprintf("aws-rds-instance/%s/%s/%s", account.AccountID, region, id), "Amazon RDS Instance ["+id+"]")
}

func newClusterRecord(account AccountContext, region string, cluster rdstypes.DBCluster, tags map[string]string, snapshots []map[string]interface{}, dynamic map[string]interface{}, sslEnforcement map[string]string, errors []CollectionError, policyInputs map[string]interface{}, collectedAt time.Time, window Window) ResourceRecord {
	id := aws.ToString(cluster.DBClusterIdentifier)
	arn := aws.ToString(cluster.DBClusterArn)
	resource := ResourceIdentity{
		ID:            id,
		ARN:           arn,
		Type:          "db-cluster",
		Engine:        aws.ToString(cluster.Engine),
		EngineVersion: aws.ToString(cluster.EngineVersion),
	}
	config := map[string]interface{}{
		"db_cluster_identifier":               id,
		"db_cluster_arn":                      arn,
		"engine":                              aws.ToString(cluster.Engine),
		"engine_version":                      aws.ToString(cluster.EngineVersion),
		"storage_encrypted":                   aws.ToBool(cluster.StorageEncrypted),
		"kms_key_id":                          aws.ToString(cluster.KmsKeyId),
		"multi_az":                            aws.ToBool(cluster.MultiAZ),
		"availability_zones":                  cluster.AvailabilityZones,
		"backup_retention_period":             aws.ToInt32(cluster.BackupRetentionPeriod),
		"preferred_backup_window":             aws.ToString(cluster.PreferredBackupWindow),
		"latest_restorable_time":              formatTime(cluster.LatestRestorableTime),
		"deletion_protection":                 aws.ToBool(cluster.DeletionProtection),
		"iam_database_authentication_enabled": aws.ToBool(cluster.IAMDatabaseAuthenticationEnabled),
		"enabled_cloudwatch_logs_exports":     stringSliceOrEmpty(cluster.EnabledCloudwatchLogsExports),
		"db_cluster_parameter_group":          aws.ToString(cluster.DBClusterParameterGroup),
		"ssl_enforcement":                     sslEnforcement,
		"db_cluster_members":                  cluster.DBClusterMembers,
		"vpc_security_groups":                 cluster.VpcSecurityGroups,
	}
	return newResourceRecord(account, region, resource, config, tags, snapshots, dynamic, errors, policyInputs, collectedAt, window, cluster, "aws-rds-cluster", fmt.Sprintf("aws-rds-cluster/%s/%s/%s", account.AccountID, region, id), "Amazon RDS Cluster ["+id+"]")
}

func newSnapshotRecord(account AccountContext, region string, resource ResourceIdentity, config map[string]interface{}, tags map[string]string, dynamic map[string]interface{}, errors []CollectionError, policyInputs map[string]interface{}, collectedAt time.Time, window Window, raw interface{}) ResourceRecord {
	snapshots := []map[string]interface{}{config}
	record := newResourceRecord(account, region, resource, config, tags, snapshots, dynamic, errors, policyInputs, collectedAt, window, raw, "aws-rds-snapshot", fmt.Sprintf("aws-rds-snapshot/%s/%s/%s/%s", account.AccountID, region, resource.Type, resource.ID), "Amazon RDS Snapshot ["+resource.ID+"]")
	record.InventoryType = "snapshot"
	return record
}

func newResourceRecord(account AccountContext, region string, resource ResourceIdentity, config map[string]interface{}, tags map[string]string, snapshots []map[string]interface{}, dynamic map[string]interface{}, errors []CollectionError, policyInputs map[string]interface{}, collectedAt time.Time, window Window, raw interface{}, subjectName string, subjectID string, title string) ResourceRecord {
	if tags == nil {
		tags = map[string]string{}
	}
	if snapshots == nil {
		snapshots = []map[string]interface{}{}
	}
	if dynamic == nil {
		dynamic = map[string]interface{}{}
	}
	if errors == nil {
		errors = []CollectionError{}
	}
	hashes := map[string]string{}
	if raw != nil {
		hashes["primary"] = hashPayload(raw)
	}
	collection := CollectionMetadata{
		CollectedAt:      collectedAt.UTC().Format(time.RFC3339),
		CollectorVersion: sourceName,
		CollectionType:   "config",
		Errors:           errors,
		RawPayloadHashes: hashes,
	}
	if window.Start != "" || window.End != "" {
		collection.CollectionType = "config_dynamic"
		collection.LookbackWindow = &window
	}
	input := NormalizedInput{
		SchemaVersion: schemaVersionV1,
		Source:        sourceName,
		Account:       account,
		Region:        RegionContext{Name: region},
		Resource:      resource,
		Config:        config,
		Dynamic:       dynamic,
		Snapshots:     snapshots,
		Tags:          tags,
		Collection:    collection,
		PolicyInputs:  clonePolicyInputs(policyInputs),
	}
	labels := map[string]string{
		"provider":      "aws",
		"type":          "rds",
		"subject":       subjectName,
		"account_id":    account.AccountID,
		"region":        region,
		"resource_id":   resource.ID,
		"resource_arn":  resource.ARN,
		"resource_type": resource.Type,
	}
	for key, value := range account.Tags {
		labels["account_tag_"+key] = value
	}
	return ResourceRecord{
		Input:         input,
		Labels:        labels,
		SubjectID:     subjectID,
		SubjectType:   proto.SubjectType_SUBJECT_TYPE_INVENTORY_ITEM,
		InventoryType: "database",
		Title:         title,
		Description:   "Amazon RDS/Aurora resource evaluated by the AWS RDS Aurora plugin.",
		Raw:           raw,
	}
}

func clonePolicyInputs(input map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(input))
	for k, v := range input {
		out[k] = v
	}
	return out
}

func stringSliceOrEmpty(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

func eventToMap(event types.Event) map[string]interface{} {
	return map[string]interface{}{
		"event_id":         aws.ToString(event.EventId),
		"event_name":       aws.ToString(event.EventName),
		"event_source":     aws.ToString(event.EventSource),
		"event_time":       formatTime(event.EventTime),
		"username":         aws.ToString(event.Username),
		"cloudtrail_event": aws.ToString(event.CloudTrailEvent),
		"resources":        event.Resources,
	}
}

func formatTime(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func hashPayload(payload interface{}) string {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

func defaultActors() []*proto.OriginActor {
	return []*proto.OriginActor{
		{
			Title: "The Continuous Compliance Framework",
			Type:  "assessment-platform",
			Links: []*proto.Link{
				{
					Href: "https://compliance-framework.github.io/docs/",
					Rel:  internal.StringAddressed("reference"),
					Text: internal.StringAddressed("The Continuous Compliance Framework"),
				},
			},
		},
		{
			Title: "Continuous Compliance Framework - AWS RDS Aurora Plugin",
			Type:  "tool",
			Links: []*proto.Link{
				{
					Href: "https://github.com/compliance-framework/plugin-aws-rds-aurora-psql",
					Rel:  internal.StringAddressed("reference"),
					Text: internal.StringAddressed("AWS RDS Aurora Plugin"),
				},
			},
		},
	}
}

func defaultComponents() []*proto.Component {
	return []*proto.Component{
		{
			Identifier:  "common-components/amazon-rds",
			Type:        "service",
			Title:       "Amazon RDS",
			Description: "Amazon RDS is a managed relational database service provided by AWS. Amazon Aurora is an RDS-compatible relational database engine.",
			Purpose:     "Provides managed relational database infrastructure evaluated for encryption, backup, availability, privacy, and access-control posture.",
		},
	}
}

func inventoryForRecord(record ResourceRecord) []*proto.InventoryItem {
	props := []*proto.Property{
		{Name: "account_id", Value: record.Input.Account.AccountID},
		{Name: "region", Value: record.Input.Region.Name},
		{Name: "resource_id", Value: record.Input.Resource.ID},
		{Name: "resource_arn", Value: record.Input.Resource.ARN},
		{Name: "resource_type", Value: record.Input.Resource.Type},
	}
	if record.Input.Resource.Engine != "" {
		props = append(props, &proto.Property{Name: "engine", Value: record.Input.Resource.Engine})
	}
	return []*proto.InventoryItem{
		{
			Identifier:  record.SubjectID,
			Type:        record.InventoryType,
			Title:       record.Title,
			Description: record.Description,
			Props:       props,
			ImplementedComponents: []*proto.InventoryItemImplementedComponent{
				{Identifier: "common-components/amazon-rds"},
			},
		},
	}
}

func subjectsForRecord(record ResourceRecord) []*proto.Subject {
	return []*proto.Subject{
		{
			Type:       proto.SubjectType_SUBJECT_TYPE_COMPONENT,
			Identifier: "common-components/amazon-rds",
		},
		{
			Type:       record.SubjectType,
			Identifier: record.SubjectID,
		},
	}
}
