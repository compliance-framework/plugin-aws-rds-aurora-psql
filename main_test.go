package main

import (
	"context"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/hashicorp/go-hclog"
)

func TestBuildSubjectTemplatesOnlyIncludesEvaluatedRDSSubjects(t *testing.T) {
	templates := buildSubjectTemplates()
	if len(templates) != 3 {
		t.Fatalf("expected three subject templates, got %d", len(templates))
	}
	names := map[string]bool{}
	for _, template := range templates {
		names[template.Name] = true
		requiredKeys := []string{"account_id", "region", "resource_id"}
		if template.Name == "aws-rds-snapshot" {
			requiredKeys = append(requiredKeys, "resource_type")
		}
		for _, key := range requiredKeys {
			if !contains(template.IdentityLabelKeys, key) {
				t.Fatalf("template %s missing identity key %s", template.Name, key)
			}
		}
	}
	for _, expected := range []string{"aws-rds-instance", "aws-rds-cluster", "aws-rds-snapshot"} {
		if !names[expected] {
			t.Fatalf("missing subject template %s", expected)
		}
	}
	if names["aws-rds-account-region"] {
		t.Fatal("account/region must not be registered as an evaluated subject")
	}
}

func TestSnapshotRecordUsesSnapshotInputAndTypeScopedIdentity(t *testing.T) {
	record := newSnapshotRecord(
		AccountContext{AccountID: "123456789012"},
		"us-east-1",
		ResourceIdentity{
			ID:   "shared-name",
			ARN:  "arn:aws:rds:us-east-1:123456789012:snapshot:shared-name",
			Type: "db-snapshot",
		},
		map[string]interface{}{
			"snapshot_identifier": "shared-name",
			"snapshot_type":       "manual",
		},
		nil,
		nil,
		nil,
		nil,
		time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC),
		Window{Start: "2026-02-14T12:00:00Z", End: "2026-05-15T12:00:00Z"},
		map[string]interface{}{"raw": "snapshot"},
	)
	if len(record.Input.Snapshots) != 1 {
		t.Fatalf("expected standalone snapshot input.snapshots to include current snapshot, got %#v", record.Input.Snapshots)
	}
	if record.Input.Snapshots[0]["snapshot_identifier"] != "shared-name" {
		t.Fatalf("unexpected snapshot payload: %#v", record.Input.Snapshots[0])
	}
	if record.SubjectID != "aws-rds-snapshot/123456789012/us-east-1/db-snapshot/shared-name" {
		t.Fatalf("snapshot subject ID is not resource-type scoped: %s", record.SubjectID)
	}
}

func TestInitUpsertsSubjectTemplates(t *testing.T) {
	api := &fakeAPIHelper{}
	plugin := &CompliancePlugin{logger: hclog.NewNullLogger()}
	if _, err := plugin.Init(&proto.InitRequest{}, api); err != nil {
		t.Fatalf("Init returned error: %v", err)
	}
	if len(api.subjectTemplates) != 3 {
		t.Fatalf("expected three upserted subject templates, got %d", len(api.subjectTemplates))
	}
}

func TestRegoInputMapDocumentsNestedPolicyInputsAndCollectionHashes(t *testing.T) {
	record := newInstanceRecord(
		AccountContext{AccountID: "123456789012", Tags: map[string]string{"id": "configured-account-tag"}},
		"us-east-1",
		rdstypes.DBInstance{
			DBInstanceIdentifier: aws.String("db-1"),
			DBInstanceArn:        aws.String("arn:aws:rds:us-east-1:123456789012:db:db-1"),
			Engine:               aws.String("postgres"),
			StorageEncrypted:     aws.Bool(true),
		},
		map[string]string{"env": "prod"},
		nil,
		map[string]interface{}{"cloudtrail_events": []interface{}{}},
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
	if input["source"] != sourceName {
		t.Fatalf("unexpected source: %#v", input["source"])
	}
	if _, ok := input["minimum_backup_retention_days"]; ok {
		t.Fatal("policy input leaked to top level")
	}
	policyInputs := input["policy_inputs"].(map[string]interface{})
	if policyInputs["minimum_backup_retention_days"].(float64) != 7 {
		t.Fatalf("unexpected policy_inputs: %#v", policyInputs)
	}
	collection := input["collection"].(map[string]interface{})
	if _, ok := collection["raw_payload_hashes"].(map[string]interface{})["primary"]; !ok {
		t.Fatalf("expected raw payload hash in collection, got %#v", collection)
	}
	if _, ok := record.Labels["primary"]; ok {
		t.Fatal("raw payload hash leaked into labels")
	}
	if record.Labels["account_id"] != "123456789012" {
		t.Fatalf("account tag overwrote account_id label: %#v", record.Labels)
	}
	if record.Labels["account_tag_id"] != "configured-account-tag" {
		t.Fatalf("expected account tag to use collision-safe prefix, got %#v", record.Labels)
	}
}

func TestPolicyLabelsCannotOverrideIdentityLabels(t *testing.T) {
	resourceLabels := map[string]string{
		"account_id":   "123456789012",
		"region":       "us-east-1",
		"resource_id":  "db-1",
		"resource_arn": "arn:aws:rds:us-east-1:123456789012:db:db-1",
	}
	policyLabels := map[string]string{
		"account_id":  "wrong",
		"region":      "wrong",
		"resource_id": "wrong",
		"team":        "security",
	}
	labels := mergeStringMaps(policyLabels, resourceLabels)
	for key, expected := range resourceLabels {
		if labels[key] != expected {
			t.Fatalf("identity label %s was overridden: %#v", key, labels)
		}
	}
	if labels["team"] != "security" {
		t.Fatalf("non-identity policy label was not preserved: %#v", labels)
	}
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

type fakeAPIHelper struct {
	evidence         []*proto.Evidence
	subjectTemplates []*proto.SubjectTemplate
	riskTemplates    map[string][]*proto.RiskTemplate
}

func (f *fakeAPIHelper) CreateEvidence(_ context.Context, evidence []*proto.Evidence) error {
	f.evidence = append(f.evidence, evidence...)
	return nil
}

func (f *fakeAPIHelper) UpsertRiskTemplates(_ context.Context, packageName string, templates []*proto.RiskTemplate) error {
	if f.riskTemplates == nil {
		f.riskTemplates = map[string][]*proto.RiskTemplate{}
	}
	f.riskTemplates[packageName] = append(f.riskTemplates[packageName], templates...)
	return nil
}

func (f *fakeAPIHelper) UpsertSubjectTemplates(_ context.Context, templates []*proto.SubjectTemplate) error {
	f.subjectTemplates = append(f.subjectTemplates, templates...)
	return nil
}
