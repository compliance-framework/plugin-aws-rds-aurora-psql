package main

import "testing"

func TestParsePluginConfigDefaults(t *testing.T) {
	cfg, err := parsePluginConfig(map[string]string{})
	if err != nil {
		t.Fatalf("parsePluginConfig returned error: %v", err)
	}
	if cfg.LookbackDays != defaultLookbackDays {
		t.Fatalf("expected default lookback %d, got %d", defaultLookbackDays, cfg.LookbackDays)
	}
	if cfg.MaxConcurrency != defaultMaxConcurrency {
		t.Fatalf("expected default max concurrency %d, got %d", defaultMaxConcurrency, cfg.MaxConcurrency)
	}
	if len(cfg.Accounts) != 0 {
		t.Fatalf("expected empty accounts to mean SDK default account, got %#v", cfg.Accounts)
	}
	if len(cfg.PolicyInputs) != 0 {
		t.Fatalf("expected empty policy inputs, got %#v", cfg.PolicyInputs)
	}
}

func TestParsePluginConfigStructuredFields(t *testing.T) {
	cfg, err := parsePluginConfig(map[string]string{
		"accounts":            `[{"account_id":"123456789012","regions":["us-east-1","us-west-2"],"role_arn":"arn:aws:iam::123456789012:role/read","external_id":"ext","session_name":"ccf","tags":{"env":"prod"}}]`,
		"default_regions":     `["eu-west-1"]`,
		"lookback_days":       "30",
		"policy_inputs":       `{"minimum_backup_retention_days":7,"approved_snapshot_accounts":["111111111111"]}`,
		"policy_labels":       `{"team":"security"}`,
		"max_concurrency":     "2",
		"api_timeout_seconds": "15",
	})
	if err != nil {
		t.Fatalf("parsePluginConfig returned error: %v", err)
	}
	if got := cfg.Accounts[0].RoleARN; got != "arn:aws:iam::123456789012:role/read" {
		t.Fatalf("unexpected role arn %q", got)
	}
	if got := cfg.Accounts[0].ExternalID; got != "ext" {
		t.Fatalf("unexpected external id %q", got)
	}
	if got := cfg.PolicyInputs["minimum_backup_retention_days"].(float64); got != 7 {
		t.Fatalf("unexpected policy input value %v", got)
	}
	if got := cfg.PolicyLabels["team"]; got != "security" {
		t.Fatalf("unexpected policy label %q", got)
	}
	if cfg.MaxConcurrency != 2 || cfg.APITimeoutSeconds != 15 {
		t.Fatalf("unexpected operational limits: %#v", cfg)
	}
}

func TestParsePluginConfigRejectsInvalidJSONAndIntegers(t *testing.T) {
	if _, err := parsePluginConfig(map[string]string{"accounts": "{"}); err == nil {
		t.Fatal("expected invalid accounts JSON to fail")
	}
	if _, err := parsePluginConfig(map[string]string{"policy_inputs": "{"}); err == nil {
		t.Fatal("expected invalid policy_inputs JSON to fail")
	}
	if _, err := parsePluginConfig(map[string]string{"lookback_days": "0"}); err == nil {
		t.Fatal("expected non-positive lookback_days to fail")
	}
}

func TestEffectiveAccountsAndRegionsUseSDKDefaults(t *testing.T) {
	cfg, err := parsePluginConfig(map[string]string{})
	if err != nil {
		t.Fatalf("parsePluginConfig returned error: %v", err)
	}
	accounts := effectiveAccounts(cfg)
	if len(accounts) != 1 {
		t.Fatalf("expected one synthetic default account, got %d", len(accounts))
	}
	regions := effectiveRegions(accounts[0], cfg, "us-east-2")
	if len(regions) != 1 || regions[0] != "us-east-2" {
		t.Fatalf("expected SDK default region, got %#v", regions)
	}
}

func TestEffectiveRegionsPreferAccountThenDefaultRegions(t *testing.T) {
	cfg, err := parsePluginConfig(map[string]string{
		"default_regions": `["us-west-1"]`,
		"accounts":        `[{"account_id":"123","regions":["us-east-1"]},{"account_id":"456"}]`,
	})
	if err != nil {
		t.Fatalf("parsePluginConfig returned error: %v", err)
	}
	if got := effectiveRegions(cfg.Accounts[0], cfg, "eu-west-1"); got[0] != "us-east-1" {
		t.Fatalf("expected account region, got %#v", got)
	}
	if got := effectiveRegions(cfg.Accounts[1], cfg, "eu-west-1"); got[0] != "us-west-1" {
		t.Fatalf("expected default region, got %#v", got)
	}
}
