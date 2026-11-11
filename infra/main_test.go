package main

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/jsii-runtime-go"
)

// synth builds the stack with a dummy account (no credentials needed) and
// returns its template's resources.
func synth(t *testing.T) map[string]map[string]any {
	t.Helper()
	t.Setenv("CDK_DEFAULT_ACCOUNT", "000000000000")
	app := awscdk.NewApp(nil)
	stack := NewSkylightStack(app, "SkylightMcp", &awscdk.StackProps{
		Env: &awscdk.Environment{Account: jsii.String("000000000000"), Region: jsii.String(region)},
	})
	b, err := json.Marshal(app.Synth(nil).GetStackArtifact(stack.ArtifactId()).Template())
	if err != nil {
		t.Fatal(err)
	}
	var tpl struct {
		Resources map[string]map[string]any `json:"Resources"`
	}
	if err := json.Unmarshal(b, &tpl); err != nil {
		t.Fatal(err)
	}
	return tpl.Resources
}

func find(t *testing.T, res map[string]map[string]any, typ, prefix string) string {
	t.Helper()
	for id, r := range res {
		if r["Type"] == typ && strings.HasPrefix(id, prefix) {
			return id
		}
	}
	t.Fatalf("no %s with logical id prefix %s", typ, prefix)
	return ""
}

func dependsOn(r map[string]any) []string {
	var out []string
	switch d := r["DependsOn"].(type) {
	case string:
		out = append(out, d)
	case []any:
		for _, x := range d {
			out = append(out, x.(string))
		}
	}
	return out
}

// Regression: the first pipeline deploy rolled back because the alias update
// (a CodeDeploy deployment) raced the policy that lets CodeDeploy invoke the
// pre-traffic hook.
func TestAliasWaitsForCodeDeployInvokeGrant(t *testing.T) {
	res := synth(t)
	alias := find(t, res, "AWS::Lambda::Alias", "LiveAlias")
	policy := find(t, res, "AWS::IAM::Policy", "DeployGroupServiceRoleDefaultPolicy")
	role := find(t, res, "AWS::IAM::Role", "DeployGroupServiceRole")
	deps := dependsOn(res[alias])
	if !slices.Contains(deps, policy) || !slices.Contains(deps, role) {
		t.Fatalf("alias DependsOn %v must include %s and %s", deps, policy, role)
	}
	if _, ok := res[alias]["UpdatePolicy"].(map[string]any)["CodeDeployLambdaAliasUpdate"]; !ok {
		t.Fatal("alias is not updated through CodeDeploy")
	}
}

// Every IAM role in the stack carries the permissions boundary the scoped
// CloudFormation execution policy requires.
func TestEveryRoleHasTheBoundary(t *testing.T) {
	for id, r := range synth(t) {
		if r["Type"] != "AWS::IAM::Role" {
			continue
		}
		props, _ := r["Properties"].(map[string]any)
		if _, ok := props["PermissionsBoundary"]; !ok {
			t.Errorf("role %s has no permissions boundary", id)
		}
	}
}
