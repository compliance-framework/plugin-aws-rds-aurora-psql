package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/rds/types"
	policyManager "github.com/compliance-framework/agent/policy-manager"
	"github.com/compliance-framework/agent/runner"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/compliance-framework/plugin-aws-rds-aurora-psql/internal"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
	"iter"
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

func (l *CompliancePlugin) EvaluatePolicies(ctx context.Context, request *proto.EvalRequest) ([]*proto.Evidence, error) {
	var accumulatedErrors error

	activities := make([]*proto.Activity, 0)
	evidences := make([]*proto.Evidence, 0)

	activities = append(activities, &proto.Activity{
		Title:       "Collected RDS cluster info",
		Description: "Collected RDS cluster info and prepare collected data for validation in policy engine",
		Steps: []*proto.Step{
			{
				Title:       "Fetched RDS cluster info",
				Description: "Fetched RDS cluster info using AWS SDK.",
			},
		},
	})

	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(os.Getenv("AWS_REGION")))
	if err != nil {
		l.logger.Error("unable to load SDK config", "error", err)
		accumulatedErrors = errors.Join(accumulatedErrors, err)
	}
	client := rds.NewFromConfig(cfg)
	for cluster, err := range getAuroraInstances(ctx, client) {
		if err != nil {
			l.logger.Error("unable to get cluster", "error", err)
			accumulatedErrors = errors.Join(accumulatedErrors, err)
			break
		}

		labels := map[string]string{
			"provider":        "aws",
			"type":            "rds",
			"cluster":         aws.ToString(cluster.DBClusterIdentifier),
			"engine":          aws.ToString(cluster.Engine),
			"_engine-version": aws.ToString(cluster.EngineVersion),
		}

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
			},
			{
				Title: "Continuous Compliance Framework - Local SSH Plugin",
				Type:  "tool",
				Links: []*proto.Link{
					{
						Href: "https://github.com/compliance-framework/plugin-local-ssh",
						Rel:  internal.StringAddressed("reference"),
						Text: internal.StringAddressed("The Continuous Compliance Framework' Local SSH Plugin"),
					},
				},
			},
		}
		components := []*proto.Component{
			{
				Identifier:  "common-components/amazon-rds",
				Type:        "service",
				Title:       "Amazon RDS",
				Description: "Amazon RDS is a managed relational database service provided by AWS that supports engines like PostgreSQL, MySQL, SQL Server, and others. It automates common database administration tasks such as provisioning, backups, patching, scaling, and monitoring. RDS provides integrated features for encryption, high availability, and network isolation.",
				Purpose:     "To provide scalable, secure, and managed relational database infrastructure that supports application data storage with minimal administrative overhead, enabling compliance with availability, confidentiality, and integrity requirements.",
			},
		}
		inventory := []*proto.InventoryItem{
			{
				Identifier: fmt.Sprintf("aws-rds/%s", aws.ToString(cluster.DBClusterIdentifier)),
				Type:       "database",
				Title:      fmt.Sprintf("Amazon RDS Cluster [%s]", aws.ToString(cluster.DBClusterIdentifier)),
				Props: []*proto.Property{
					{
						Name:  "cluster",
						Value: aws.ToString(cluster.DBClusterIdentifier),
					},
					{
						Name:  "engine",
						Value: aws.ToString(cluster.Engine),
					},
					{
						Name:  "engine-version",
						Value: aws.ToString(cluster.EngineVersion),
					},
				},
				ImplementedComponents: []*proto.InventoryItemImplementedComponent{
					{
						Identifier: "common-components/amazon-rds",
					},
				},
			},
		}
		subjects := []*proto.Subject{
			{
				Type:       proto.SubjectType_SUBJECT_TYPE_COMPONENT,
				Identifier: "common-components/amazon-rds",
			},
			{
				Type:       proto.SubjectType_SUBJECT_TYPE_INVENTORY_ITEM,
				Identifier: fmt.Sprintf("aws-rds/%s", aws.ToString(cluster.DBClusterIdentifier)),
			},
		}

		for _, policyPath := range request.GetPolicyPaths() {

			// Explicitly reset steps to make things readable
			processor := policyManager.NewPolicyProcessor(
				l.logger,
				internal.MergeMaps(
					labels,
					map[string]string{},
				),
				subjects,
				components,
				inventory,
				actors,
				activities,
			)
			evidence, err := processor.GenerateResults(ctx, policyPath, cluster)
			evidences = slices.Concat(evidences, evidence)
			if err != nil {
				accumulatedErrors = errors.Join(accumulatedErrors, err)
			}
		}
	}

	return evidences, accumulatedErrors
}

func (l *CompliancePlugin) Eval(request *proto.EvalRequest, apiHelper runner.ApiHelper) (*proto.EvalResponse, error) {
	ctx := context.TODO()

	evidences, err := l.EvaluatePolicies(ctx, request)
	if err != nil {
		return &proto.EvalResponse{
			Status: proto.ExecutionStatus_FAILURE,
		}, err
	}
	if err = apiHelper.CreateEvidence(ctx, evidences); err != nil {
		l.logger.Error("Failed to send compliance evidence", "error", err)
		return &proto.EvalResponse{
			Status: proto.ExecutionStatus_FAILURE,
		}, err
	}

	return &proto.EvalResponse{
		Status: proto.ExecutionStatus_SUCCESS,
	}, err
}

func getAuroraInstances(ctx context.Context, client *rds.Client) iter.Seq2[types.DBCluster, error] {
	return func(yield func(types.DBCluster, error) bool) {
		out, err := client.DescribeDBClusters(ctx, &rds.DescribeDBClustersInput{})
		if err != nil {
			yield(types.DBCluster{}, err)
			return
		}

		for _, cluster := range out.DBClusters {
			if !yield(cluster, nil) {
				return
			}
		}
	}
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
	logger.Debug("Initiating AWS RDS Aurora plugin")

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
