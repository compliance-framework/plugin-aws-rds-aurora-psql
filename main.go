package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	policyManager "github.com/compliance-framework/agent/policy-manager"
	"github.com/compliance-framework/agent/runner"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/compliance-framework/plugin-aws-rds-aurora-psql/internal"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
	"os"
	"slices"
)

type CompliancePlugin struct {
	logger hclog.Logger
	config map[string]string
}

type Tag struct {
	Key   string `json:"Key"`
	Value string `json:"Value"`
}

func (l *CompliancePlugin) Configure(req *proto.ConfigureRequest) (*proto.ConfigureResponse, error) {
	l.config = req.GetConfig()
	return &proto.ConfigureResponse{}, nil
}

func (l *CompliancePlugin) EvaluatePolicies(ctx context.Context, request *proto.EvalRequest) ([]*proto.Observation, []*proto.Finding, error) {
	var accumulatedErrors error

	activities := make([]*proto.Activity, 0)
	findings := make([]*proto.Finding, 0)
	observations := make([]*proto.Observation, 0)

	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(os.Getenv("AWS_REGION")))
	if err != nil {
		l.logger.Error("unable to load SDK config", "error", err)
		accumulatedErrors = errors.Join(accumulatedErrors, err)
	}

	svc := rds.NewFromConfig(cfg)

	clusters, err := svc.DescribeDBClusters(ctx, &rds.DescribeDBClustersInput{})
	if err != nil {
		l.logger.Error("unable to list DB clusters", "error", err)
		accumulatedErrors = errors.Join(accumulatedErrors, err)
	}

	RDSConfigSteps := make([]*proto.Step, 0)
	RDSConfigSteps = append(RDSConfigSteps, &proto.Step{
		Title:       "Fetched RDS cluster info",
		Description: "Fetched RDS cluster info using AWS SDK.",
	})
	activities = append(activities, &proto.Activity{
		Title:       "Collected RDS cluster info",
		Description: "Collected RDS cluster info and prepare collected data for validation in policy engine",
		Steps:       RDSConfigSteps,
	})

	var RDSInstances []map[string]interface{}
	for _, cluster := range clusters.DBClusters {
		l.logger.Debug("ClusterID: ", *cluster.DBClusterIdentifier)
		RDSInstances = append(RDSInstances, map[string]interface{}{
			"DBClusterIdentifier":              *cluster.DBClusterIdentifier,
			"Engine":                           *cluster.Engine,
			"PubliclyAccessible":               cluster.PubliclyAccessible,
			"MultiAZ":                          cluster.MultiAZ,
			"BackupRetentionPeriod":            cluster.BackupRetentionPeriod,
			"EnabledCloudwatchLogsExports":     cluster.EnabledCloudwatchLogsExports,
			"IamDatabaseAuthenticationEnabled": cluster.IAMDatabaseAuthenticationEnabled,
			"AutoMinorVersionUpgrade":          cluster.AutoMinorVersionUpgrade,
		})
	}

	l.logger.Trace("evaluating data", RDSInstances)
	for _, instance := range RDSInstances {

		actors := []*proto.OriginActor{
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
				Props: nil,
			},
			{
				Title: "Continuous Compliance Framework - AWS RDS Aurora PSQL Plugin",
				Type:  "tool",
				Links: []*proto.Link{
					{
						Href: "https://github.com/compliance-framework/plugin-aws-rds-aurora-psql",
						Rel:  internal.StringAddressed("reference"),
						Text: internal.StringAddressed("The Continuous Compliance Framework' AWS RDS Aurora PSQL Plugin"),
					},
				},
				Props: nil,
			},
		}
		components := []*proto.ComponentReference{
			{
				Identifier: "common-components/aws-rds-aurora-psql",
			},
		}

		labels := map[string]string{
			"type":       "aws-rds-aurora-psql",
			"service":    "rds",
			"cluster-id": fmt.Sprintf("%v", instance["DBClusterIdentifier"]),
		}
		subjects := []*proto.SubjectReference{
			{
				Type: "aws-rds-aurora-psql",
				Attributes: map[string]string{
					"type":       "aws",
					"service":    "rds",
					"engine":     fmt.Sprintf("%v", instance["Engine"]),
					"cluster_id": fmt.Sprintf("%v", instance["DBClusterIdentifier"]),
				},
				Title:   internal.StringAddressed("RDS Instance"),
				Remarks: internal.StringAddressed("Plugin running checks against AWS RDS configuration"),
				Props: []*proto.Property{
					{
						Name:    "aws-rds-aurora-psql",
						Value:   "CCF",
						Remarks: internal.StringAddressed("The Aurora PSQL RDS cluster of which the policy was executed against"),
					},
				},
			},
		}

		for _, policyPath := range request.GetPolicyPaths() {

			// Explicitly reset steps to make things readable
			processor := policyManager.NewPolicyProcessor(
				l.logger,
				internal.MergeMaps(
					labels,
					map[string]string{
						"_policy_path": policyPath,
					},
				),
				subjects,
				components,
				actors,
				activities,
			)
			obs, finds, err := processor.GenerateResults(ctx, policyPath, instance)
			observations = slices.Concat(observations, obs)
			findings = slices.Concat(findings, finds)
			if err != nil {
				accumulatedErrors = errors.Join(accumulatedErrors, err)
			}

		}
	}

	return observations, findings, accumulatedErrors
}

func (l *CompliancePlugin) Eval(request *proto.EvalRequest, apiHelper runner.ApiHelper) (*proto.EvalResponse, error) {
	ctx := context.TODO()

	observations, findings, err := l.EvaluatePolicies(ctx, request)
	if err != nil {
		return &proto.EvalResponse{
			Status: proto.ExecutionStatus_FAILURE,
		}, err
	}
	if err = apiHelper.CreateFindings(ctx, findings); err != nil {
		l.logger.Error("Failed to send compliance findings", "error", err)
		return &proto.EvalResponse{
			Status: proto.ExecutionStatus_FAILURE,
		}, err
	}

	if err = apiHelper.CreateObservations(ctx, observations); err != nil {
		l.logger.Error("Failed to send compliance observations", "error", err)
		return &proto.EvalResponse{
			Status: proto.ExecutionStatus_FAILURE,
		}, err
	}

	return &proto.EvalResponse{
		Status: proto.ExecutionStatus_SUCCESS,
	}, err
}

func main() {
	logger := hclog.New(&hclog.LoggerOptions{
		Level:      hclog.Debug,
		JSONFormat: true,
	})

	compliancePluginObj := &CompliancePlugin{
		logger: logger,
	}
	// pluginMap is the map of plugins we can dispense.
	logger.Debug("Initiating AWS RDS Aurora psql plugin")

	goplugin.Serve(&goplugin.ServeConfig{
		HandshakeConfig: runner.HandshakeConfig,
		Plugins: map[string]goplugin.Plugin{
			"runner": &runner.RunnerGRPCPlugin{
				Impl: compliancePluginObj,
			},
		},
		GRPCServer: goplugin.DefaultGRPCServer,
	})
}
