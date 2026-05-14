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
		for _, key := range []string{"account_id", "region", "resource_id"} {
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
		AccountContext{AccountID: "123456789012"},
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
