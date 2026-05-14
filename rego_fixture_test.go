package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
	policyManager "github.com/compliance-framework/agent/policy-manager"
	"github.com/hashicorp/go-hclog"
)

func TestRepresentativeRegoFixturesAcrossDocumentMetrics(t *testing.T) {
	policyDir := t.TempDir()
	policies := map[string]string{
		"data_store_encryption_access.rego": `package compliance_framework.data_store_encryption_access

title := "RDS datastore encryption and access controls are configured"
description := "RDS resource uses storage encryption and a configured KMS key."

violation[{"id": "rds_storage_not_encrypted"}] if {
	input.config.storage_encrypted != true
}

violation[{"id": "rds_kms_key_missing"}] if {
	input.config.kms_key_id == ""
}
`,
		"rds_availability_backup_restore.rego": `package compliance_framework.rds_availability_backup_restore

title := "RDS backup retention satisfies availability policy"
description := "RDS backup retention is compared with policy_inputs."

minimum_retention := object.get(input.policy_inputs, "minimum_backup_retention_days", 1)

violation[{"id": "backup_retention_too_short"}] if {
	input.config.backup_retention_period < minimum_retention
}
`,
		"rds_backup_multiaz_pitr.rego": `package compliance_framework.rds_backup_multiaz_pitr

title := "RDS PITR and redundancy are configured"
description := "RDS has a restorable time and Multi-AZ posture."

violation[{"id": "pitr_missing"}] if {
	input.config.latest_restorable_time == ""
}

violation[{"id": "multi_az_missing"}] if {
	input.config.multi_az != true
}
`,
		"rds_confidential_data_controls.rego": `package compliance_framework.rds_confidential_data_controls

import future.keywords.in

title := "RDS snapshots for confidential data are protected"
description := "Snapshots are encrypted and not public."

violation[{"id": "snapshot_public"}] if {
	some snapshot in input.snapshots
	snapshot.public == true
}

violation[{"id": "snapshot_unencrypted"}] if {
	some snapshot in input.snapshots
	snapshot.encrypted != true
}
`,
		"rds_privacy_infrastructure_posture.rego": `package compliance_framework.rds_privacy_infrastructure_posture

title := "RDS privacy infrastructure posture is observable"
description := "RDS has log exports and dynamic event windows available."

violation[{"id": "log_exports_missing"}] if {
	count(input.config.enabled_cloudwatch_logs_exports) == 0
}

violation[{"id": "lookback_window_missing"}] if {
	input.collection.lookback_window.start == ""
}
`,
	}
	for name, content := range policies {
		if err := os.WriteFile(filepath.Join(policyDir, name), []byte(content), 0o644); err != nil {
			t.Fatalf("write policy %s: %v", name, err)
		}
	}

	restorable := time.Date(2026, 5, 14, 11, 30, 0, 0, time.UTC)
	record := newInstanceRecord(
		AccountContext{AccountID: "123456789012"},
		"us-east-1",
		rdstypes.DBInstance{
			DBInstanceIdentifier:         aws.String("db-1"),
			DBInstanceArn:                aws.String("arn:aws:rds:us-east-1:123456789012:db:db-1"),
			Engine:                       aws.String("postgres"),
			StorageEncrypted:             aws.Bool(true),
			KmsKeyId:                     aws.String("arn:aws:kms:us-east-1:123456789012:key/key-id"),
			MultiAZ:                      aws.Bool(true),
			BackupRetentionPeriod:        aws.Int32(7),
			LatestRestorableTime:         &restorable,
			EnabledCloudwatchLogsExports: []string{"postgresql"},
		},
		map[string]string{"owner": "data-platform"},
		[]map[string]interface{}{
			{
				"snapshot_identifier": "db-1-snapshot",
				"encrypted":           true,
				"public":              false,
			},
		},
		map[string]interface{}{
			"cloudtrail_events":  []interface{}{},
			"rds_events":         []interface{}{},
			"cloudwatch_metrics": map[string]interface{}{},
		},
		map[string]string{"default.postgres15": "1"},
		nil,
		map[string]interface{}{"minimum_backup_retention_days": 7},
		time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC),
		Window{Start: "2026-02-13T12:00:00Z", End: "2026-05-14T12:00:00Z"},
	)
	input, err := regoInputMap(record.Input)
	if err != nil {
		t.Fatalf("regoInputMap returned error: %v", err)
	}

	results, err := policyManager.New(context.Background(), hclog.NewNullLogger(), policyDir).Execute(context.Background(), input)
	if err != nil {
		t.Fatalf("policy execution failed: %v", err)
	}
	if len(results) != len(policies) {
		t.Fatalf("expected %d policy results, got %d", len(policies), len(results))
	}
	for _, result := range results {
		if len(result.Violations) != 0 {
			t.Fatalf("expected no violations for %s, got %#v", result.Policy.File, result.Violations)
		}
	}
}
