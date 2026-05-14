package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	policyManager "github.com/compliance-framework/agent/policy-manager"
	"github.com/compliance-framework/agent/runner"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
)

type CompliancePlugin struct {
	logger       hclog.Logger
	rawConfig    map[string]string
	parsedConfig *PluginConfig
	factory      AWSClientFactory
}

func (l *CompliancePlugin) Configure(req *proto.ConfigureRequest) (*proto.ConfigureResponse, error) {
	parsed, err := parsePluginConfig(req.GetConfig())
	if err != nil {
		l.logger.Error("Configuration validation failed", "error", err)
		return nil, err
	}
	l.rawConfig = req.GetConfig()
	l.parsedConfig = parsed
	return &proto.ConfigureResponse{}, nil
}

func (l *CompliancePlugin) Init(req *proto.InitRequest, apiHelper runner.ApiHelper) (*proto.InitResponse, error) {
	ctx := context.Background()
	return runner.InitWithSubjectsAndRisksFromPolicies(ctx, l.logger, req, apiHelper, buildSubjectTemplates())
}

func (l *CompliancePlugin) EvaluatePolicies(ctx context.Context, request *proto.EvalRequest) ([]*proto.Evidence, error) {
	if l.parsedConfig == nil {
		parsed, err := parsePluginConfig(l.rawConfig)
		if err != nil {
			return nil, err
		}
		l.parsedConfig = parsed
	}
	if len(request.GetPolicyPaths()) == 0 {
		return nil, errors.New("no policy paths provided")
	}

	collector := &Collector{
		Logger:  l.logger.Named("collector"),
		Config:  l.parsedConfig,
		Factory: l.factory,
	}
	result := collector.Collect(ctx)

	evidences := make([]*proto.Evidence, 0)
	var accumulated error
	accumulated = errors.Join(accumulated, result.Err)
	for _, record := range result.Records {
		recordEvidence, err := l.evaluateRecord(ctx, request.GetPolicyPaths(), record)
		evidences = append(evidences, recordEvidence...)
		accumulated = errors.Join(accumulated, err)
	}
	return evidences, accumulated
}

func (l *CompliancePlugin) evaluateRecord(ctx context.Context, policyPaths []string, record *ResourceRecord) ([]*proto.Evidence, error) {
	var accumulated error
	evidences := make([]*proto.Evidence, 0)
	labels := mergeStringMaps(record.Labels, l.parsedConfig.PolicyLabels)
	activities := []*proto.Activity{
		{
			Title:       "Collect AWS RDS evidence",
			Description: "Collected read-only Amazon RDS, Aurora, CloudTrail, RDS Events, CloudWatch, snapshot, tag, and parameter data for policy evaluation.",
			Steps: []*proto.Step{
				{
					Title:       "Fetch read-only AWS data",
					Description: "Used AWS SDK read-only APIs to collect normalized evidence for the RDS or Aurora resource.",
				},
				{
					Title:       "Normalize Rego input",
					Description: "Converted AWS SDK payloads into the documented aws-rds-aurora-psql Rego input schema.",
				},
			},
		},
	}
	input, err := regoInputMap(record.Input)
	if err != nil {
		return nil, err
	}

	for _, policyPath := range policyPaths {
		processor := policyManager.NewPolicyProcessor(
			l.logger,
			labels,
			subjectsForRecord(*record),
			defaultComponents(),
			inventoryForRecord(*record),
			defaultActors(),
			activities,
		)
		evidence, err := processor.GenerateResults(ctx, policyPath, input)
		evidences = append(evidences, evidence...)
		if err != nil {
			accumulated = errors.Join(accumulated, err)
		}
	}

	return evidences, accumulated
}

func (l *CompliancePlugin) Eval(request *proto.EvalRequest, apiHelper runner.ApiHelper) (*proto.EvalResponse, error) {
	ctx := context.Background()

	evidences, err := l.EvaluatePolicies(ctx, request)
	if len(evidences) > 0 {
		if createErr := apiHelper.CreateEvidence(ctx, evidences); createErr != nil {
			l.logger.Error("Failed to send compliance evidence", "error", createErr)
			err = errors.Join(err, createErr)
		}
	}

	if err != nil {
		return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, err
	}
	return &proto.EvalResponse{Status: proto.ExecutionStatus_SUCCESS}, nil
}

func buildSubjectTemplates() []*proto.SubjectTemplate {
	return []*proto.SubjectTemplate{
		{
			Name:                "aws-rds-instance",
			Type:                proto.SubjectType_SUBJECT_TYPE_INVENTORY_ITEM,
			TitleTemplate:       "AWS RDS instance {{ .resource_id }} in {{ .account_id }}/{{ .region }}",
			DescriptionTemplate: "Amazon RDS DB instance {{ .resource_id }} in AWS account {{ .account_id }} and region {{ .region }}.",
			PurposeTemplate:     "Represents a managed RDS DB instance evaluated for compliance posture.",
			IdentityLabelKeys:   []string{"account_id", "region", "resource_id"},
			LabelSchema: []*proto.SubjectLabelSchema{
				{Key: "account_id", Description: "AWS account ID containing the RDS resource"},
				{Key: "region", Description: "AWS region containing the RDS resource"},
				{Key: "resource_id", Description: "RDS DB instance identifier"},
				{Key: "resource_arn", Description: "RDS DB instance ARN"},
			},
		},
		{
			Name:                "aws-rds-cluster",
			Type:                proto.SubjectType_SUBJECT_TYPE_INVENTORY_ITEM,
			TitleTemplate:       "AWS RDS cluster {{ .resource_id }} in {{ .account_id }}/{{ .region }}",
			DescriptionTemplate: "Amazon Aurora/RDS DB cluster {{ .resource_id }} in AWS account {{ .account_id }} and region {{ .region }}.",
			PurposeTemplate:     "Represents a managed RDS/Aurora DB cluster evaluated for compliance posture.",
			IdentityLabelKeys:   []string{"account_id", "region", "resource_id"},
			LabelSchema: []*proto.SubjectLabelSchema{
				{Key: "account_id", Description: "AWS account ID containing the RDS resource"},
				{Key: "region", Description: "AWS region containing the RDS resource"},
				{Key: "resource_id", Description: "RDS DB cluster identifier"},
				{Key: "resource_arn", Description: "RDS DB cluster ARN"},
			},
		},
		{
			Name:                "aws-rds-snapshot",
			Type:                proto.SubjectType_SUBJECT_TYPE_INVENTORY_ITEM,
			TitleTemplate:       "AWS RDS snapshot {{ .resource_id }} in {{ .account_id }}/{{ .region }}",
			DescriptionTemplate: "Amazon RDS/Aurora snapshot {{ .resource_id }} in AWS account {{ .account_id }} and region {{ .region }}.",
			PurposeTemplate:     "Represents an RDS snapshot evaluated for backup, encryption, and sharing posture.",
			IdentityLabelKeys:   []string{"account_id", "region", "resource_id"},
			LabelSchema: []*proto.SubjectLabelSchema{
				{Key: "account_id", Description: "AWS account ID containing the snapshot"},
				{Key: "region", Description: "AWS region containing the snapshot"},
				{Key: "resource_id", Description: "RDS snapshot identifier"},
				{Key: "resource_arn", Description: "RDS snapshot ARN"},
			},
		},
	}
}

func regoInputMap(input NormalizedInput) (map[string]interface{}, error) {
	encoded, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("marshal Rego input: %w", err)
	}
	result := map[string]interface{}{}
	if err := json.Unmarshal(encoded, &result); err != nil {
		return nil, fmt.Errorf("unmarshal Rego input: %w", err)
	}
	return result, nil
}

func mergeStringMaps(maps ...map[string]string) map[string]string {
	result := map[string]string{}
	for _, m := range maps {
		for k, v := range m {
			result[k] = v
		}
	}
	return result
}

func main() {
	logger := hclog.New(&hclog.LoggerOptions{
		Level:      hclog.Debug,
		JSONFormat: true,
	})

	compliancePluginObj := &CompliancePlugin{logger: logger}
	logger.Debug("Initiating AWS RDS Aurora plugin")

	goplugin.Serve(&goplugin.ServeConfig{
		HandshakeConfig: runner.HandshakeConfig,
		Plugins: map[string]goplugin.Plugin{
			"runner": &runner.RunnerV2GRPCPlugin{
				Impl: compliancePluginObj,
			},
		},
		GRPCServer: goplugin.DefaultGRPCServer,
	})
}
