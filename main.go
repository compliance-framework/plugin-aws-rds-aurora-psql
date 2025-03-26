package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	policyManager "github.com/compliance-framework/agent/policy-manager"
	"github.com/compliance-framework/agent/runner"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/compliance-framework/configuration-service/sdk"
	"github.com/compliance-framework/plugin-aws-rds-aurora-psql/internal"
	"github.com/google/uuid"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
	"google.golang.org/protobuf/types/known/timestamppb"
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
	startTime := time.Now()
	var errAcc error

	activities := make([]*proto.Activity, 0)
	findings := make([]*proto.Finding, 0)
	observations := make([]*proto.Observation, 0)

	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(os.Getenv("AWS_REGION")))
	if err != nil {
		l.logger.Error("unable to load SDK config", "error", err)
		errAcc = errors.Join(errAcc, err)
	}

	svc := rds.NewFromConfig(cfg)

	clusters, err := svc.DescribeDBClusters(ctx, &rds.DescribeDBClustersInput{})
	if err != nil {
		l.logger.Error("unable to list DB clusters", "error", err)
		errAcc = errors.Join(errAcc, err)
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
			"PubliclyAccessible":               cluster.PubliclyAccessible,
			"MultiAZ":                          cluster.MultiAZ,
			"BackupRetentionPeriod":            cluster.BackupRetentionPeriod,
			"EnabledCloudwatchLogsExports":     cluster.EnabledCloudwatchLogsExports,
			"IamDatabaseAuthenticationEnabled": cluster.IAMDatabaseAuthenticationEnabled,
			"AutoMinorVersionUpgrade":          cluster.AutoMinorVersionUpgrade,
		})
	}

	l.logger.Debug("evaluating data", RDSInstances)
	for _, instance := range RDSInstances {
		for _, policyPath := range request.GetPolicyPaths() {
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
			subjectAttributeMap := map[string]string{
				"type":       "aws",
				"service":    "rds-aurora-psql",
				"cluster_id": fmt.Sprintf("%v", instance["DBClusterIdentifier"]),
			}

			subjects := []*proto.SubjectReference{
				{
					Type:       "aws-rds-aurora-psql",
					Attributes: subjectAttributeMap,
					Title:      internal.StringAddressed("RDS Instance"),
					Remarks:    internal.StringAddressed("Plugin running checks against AWS RDS configuration"),
					Props: []*proto.Property{
						{
							Name:    "aws-rds-aurora-psql",
							Value:   "CCF",
							Remarks: internal.StringAddressed("The Aurora PSQL RDS cluster of which the policy was executed against"),
						},
					},
				},
			}
			results, err := policyManager.New(ctx, l.logger, policyPath).Execute(ctx, "compliance_plugin", instance)
			if err != nil {
				l.logger.Error("policy evaluation for RDS failed", "error", err)
				errAcc = errors.Join(errAcc, err)
				return observations, findings, errAcc
			}
			policyBundleSteps := make([]*proto.Step, 0)
			policyBundleSteps = append(policyBundleSteps, &proto.Step{
				Title:       "Compile policy bundle",
				Description: "Using a locally addressable policy path, compile the policy files to an in memory executable.",
			})
			policyBundleSteps = append(policyBundleSteps, &proto.Step{
				Title:       "Execute policy bundle",
				Description: "Using previously collected JSON-formatted Aurora PSQL RDS configurations, execute the compiled policies",
			})
			activities = append(activities, &proto.Activity{
				Title:       "Execute policy",
				Description: "Prepare and compile policy bundles, and execute them using the prepared Aurora PSQL RDS configuration data",
				Steps:       policyBundleSteps,
			})
			l.logger.Debug("local kubernetes Aurora PSQL RDS policy runs completed", "results", results)

			activities = append(activities, &proto.Activity{
				Title:       "Compile Results",
				Description: "Using the output from policy execution, compile the resulting output to Observations and Findings, marking any violations, risks, and other OSCAL-familiar data",
				Steps:       policyBundleSteps,
			})

			for _, result := range results {
				observationUUIDMap := internal.MergeMaps(subjectAttributeMap, map[string]string{
					"type":        "observation",
					"policy":      result.Policy.Package.PurePackage(),
					"policy_file": result.Policy.File,
					"policy_path": policyPath,
				})
				observationUUID, err := sdk.SeededUUID(observationUUIDMap)
				if err != nil {
					errAcc = errors.Join(errAcc, err)
					// We've been unable to do much here, but let's try the next one regardless.
					continue
				}

				findingUUIDMap := internal.MergeMaps(subjectAttributeMap, map[string]string{
					"type":        "finding",
					"policy":      result.Policy.Package.PurePackage(),
					"policy_file": result.Policy.File,
					"policy_path": policyPath,
				})
				findingUUID, err := sdk.SeededUUID(findingUUIDMap)
				if err != nil {
					errAcc = errors.Join(errAcc, err)
					// We've been unable to do much here, but let's try the next one regardless.
					continue
				}

				observation := proto.Observation{
					ID:         uuid.New().String(),
					UUID:       observationUUID.String(),
					Collected:  timestamppb.New(startTime),
					Expires:    timestamppb.New(startTime.Add(24 * time.Hour)),
					Origins:    []*proto.Origin{{Actors: actors}},
					Subjects:   subjects,
					Activities: activities,
					Components: components,
					RelevantEvidence: []*proto.RelevantEvidence{
						{
							Description: fmt.Sprintf("Policy %v was executed against the RDS instance configuration, using the aws-rds-aurora-psql Compliance Plugin", result.Policy.Package.PurePackage()),
						},
					},
				}

				newFinding := func() *proto.Finding {
					return &proto.Finding{
						ID:        uuid.New().String(),
						UUID:      findingUUID.String(),
						Collected: timestamppb.New(time.Now()),
						Labels: map[string]string{
							"type":         "aws-rds-aurora-psql",
							"host":         "CCF cluster",
							"_policy":      result.Policy.Package.PurePackage(),
							"_policy_path": result.Policy.File,
						},
						Origins:             []*proto.Origin{{Actors: actors}},
						Subjects:            subjects,
						Components:          components,
						RelatedObservations: []*proto.RelatedObservation{{ObservationUUID: observation.ID}},
						Controls:            nil,
					}
				}

				if len(result.Violations) == 0 {
					observation.Title = internal.StringAddressed(fmt.Sprintf("AWS RDS Aurora instance Validation on %s passed.", result.Policy.Package.PurePackage()))
					observation.Description = fmt.Sprintf("Observed no violations on the %s policy within the aws-rds-aurora-psql Compliance Plugin.", result.Policy.Package.PurePackage())
					observations = append(observations, &observation)

					finding := newFinding()
					finding.Title = fmt.Sprintf("No violations found on %s", result.Policy.Package.PurePackage())
					finding.Description = fmt.Sprintf("No violations found on the %s policy within the AWS RDS Aurora Compliance Plugin.", result.Policy.Package.PurePackage())
					finding.Status = &proto.FindingStatus{
						State: runner.FindingTargetStatusSatisfied,
					}
					findings = append(findings, finding)
					continue
				}

				if len(result.Violations) > 0 {
					observation.Title = internal.StringAddressed(fmt.Sprintf("Validation on %s failed.", result.Policy.Package.PurePackage()))
					observation.Description = fmt.Sprintf("Observed %d violation(s) on the %s policy within the AWS RDS Aurora Compliance Plugin.", len(result.Violations), result.Policy.Package.PurePackage())
					observations = append(observations, &observation)

					for _, violation := range result.Violations {
						finding := newFinding()
						finding.Title = violation.Title
						finding.Description = violation.Description
						finding.Remarks = internal.StringAddressed(violation.Remarks)
						finding.Status = &proto.FindingStatus{
							State: runner.FindingTargetStatusNotSatisfied,
						}
						findings = append(findings, finding)
					}
				}
			}

		}
	}

	return observations, findings, errAcc
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
