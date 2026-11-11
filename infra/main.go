// Command infra is the CDK app for skylight-mcp.
//
// Deploy-time inputs come from CDK context (never committed, because this
// repository is public):
//
//	-c userEmail=<address of the one Cognito user>
//	-c allowedSub=<that user's Cognito sub>   (optional on first deploy)
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsapigatewayv2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsapigatewayv2authorizers"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsapigatewayv2integrations"
	"github.com/aws/aws-cdk-go/awscdk/v2/awscognito"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsiam"
	"github.com/aws/aws-cdk-go/awscdk/v2/awslambda"
	"github.com/aws/aws-cdk-go/awscdk/v2/awslogs"
	"github.com/aws/constructs-go/constructs/v10"
	"github.com/aws/jsii-runtime-go"
)

const (
	region           = "us-east-2"
	resourceServerID = "skylight-mcp"
	scopeName        = "invoke" // token scope: "skylight-mcp/invoke"
)

// Claude's custom-connector OAuth callbacks.
var callbackURLs = []*string{
	jsii.String("https://claude.ai/api/mcp/auth_callback"),
	jsii.String("https://claude.com/api/mcp/auth_callback"),
}

func ctxString(scope constructs.Construct, key string) string {
	if v, ok := scope.Node().TryGetContext(jsii.String(key)).(string); ok {
		return v
	}
	return ""
}

func NewSkylightStack(scope constructs.Construct, id string, props *awscdk.StackProps) awscdk.Stack {
	stack := awscdk.NewStack(scope, &id, props)

	// Every IAM role in this stack carries the boundary created by
	// scripts/bootstrap-cdk.sh; the CloudFormation execution policy refuses to
	// create or grant permissions to a role without it.
	awsiam.PermissionsBoundary_Of(stack).Apply(
		awsiam.ManagedPolicy_FromManagedPolicyName(stack, jsii.String("RoleBoundary"), jsii.String("SkylightMcpRoleBoundary")))

	// Optional and transitional: only used to keep the original Cognito user
	// resource (retained) until it is dropped from the template. New users are
	// created by scripts/create-cognito-user.sh, so synth needs no email.
	userEmail := ctxString(stack, "userEmail")
	allowedSub := ctxString(stack, "allowedSub")

	// ---- Cognito: one user, no self-signup, password + TOTP MFA ----------
	pool := awscognito.NewUserPool(stack, jsii.String("Pool"), &awscognito.UserPoolProps{
		UserPoolName:      jsii.String("skylight-mcp"),
		SelfSignUpEnabled: jsii.Bool(false),
		SignInAliases:     &awscognito.SignInAliases{Email: jsii.Bool(true)},
		Mfa:               awscognito.Mfa_REQUIRED,
		MfaSecondFactor:   &awscognito.MfaSecondFactor{Otp: jsii.Bool(true), Sms: jsii.Bool(false)},
		PasswordPolicy: &awscognito.PasswordPolicy{
			MinLength:        jsii.Number(14),
			RequireLowercase: jsii.Bool(true),
			RequireUppercase: jsii.Bool(true),
			RequireDigits:    jsii.Bool(true),
			RequireSymbols:   jsii.Bool(true),
		},
		AccountRecovery:    awscognito.AccountRecovery_EMAIL_ONLY,
		DeletionProtection: jsii.Bool(true),
		RemovalPolicy:      awscdk.RemovalPolicy_RETAIN,
	})

	// The hosted-UI domain prefix must be unique in the region; derive it from
	// the account so it is stable and nothing identifying is committed.
	// A wrong or empty account would silently change the prefix and replace
	// the domain, so refuse to synthesise without one.
	acct := os.Getenv("CDK_DEFAULT_ACCOUNT")
	if acct == "" {
		panic("CDK_DEFAULT_ACCOUNT is empty; use scripts/deploy.sh, or a dummy account for an offline synth")
	}
	sum := sha256.Sum256([]byte(acct + "skylight-mcp"))
	domain := pool.AddDomain(jsii.String("Domain"), &awscognito.UserPoolDomainOptions{
		CognitoDomain: &awscognito.CognitoDomainOptions{
			DomainPrefix: jsii.String("skylight-mcp-" + hex.EncodeToString(sum[:])[:10]),
		},
	})

	// One custom scope for this server. No OpenID scopes: no ID token is
	// issued, so nothing contradicts the issuer the server advertises.
	invoke := awscognito.NewResourceServerScope(&awscognito.ResourceServerScopeProps{
		ScopeName:        jsii.String(scopeName),
		ScopeDescription: jsii.String("Call the skylight-mcp tools"),
	})
	resourceServer := pool.AddResourceServer(jsii.String("ResourceServer"), &awscognito.UserPoolResourceServerOptions{
		Identifier: jsii.String(resourceServerID),
		Scopes:     &[]awscognito.ResourceServerScope{invoke},
	})

	// "V2": a new logical id replaces the Step 0 client, giving a fresh client
	// id and secret (the old secret appeared in a session transcript).
	client := pool.AddClient(jsii.String("ConnectorClientV2"), &awscognito.UserPoolClientOptions{
		UserPoolClientName: jsii.String("claude-connector"),
		GenerateSecret:     jsii.Bool(true),
		OAuth: &awscognito.OAuthSettings{
			Flows:        &awscognito.OAuthFlows{AuthorizationCodeGrant: jsii.Bool(true)},
			Scopes:       &[]awscognito.OAuthScope{awscognito.OAuthScope_ResourceServer(resourceServer, invoke)},
			CallbackUrls: &callbackURLs,
		},
		SupportedIdentityProviders: &[]awscognito.UserPoolClientIdentityProvider{awscognito.UserPoolClientIdentityProvider_COGNITO()},
		AccessTokenValidity:        awscdk.Duration_Hours(jsii.Number(1)),
		IdTokenValidity:            awscdk.Duration_Hours(jsii.Number(1)),
		RefreshTokenValidity:       awscdk.Duration_Days(jsii.Number(365)),
		EnableTokenRevocation:      jsii.Bool(true),
		PreventUserExistenceErrors: jsii.Bool(true),
	})
	cfnClient := client.Node().DefaultChild().(awscognito.CfnUserPoolClient)
	// Only the hosted-UI OAuth flow is used; disable direct SRP/password/custom
	// sign-in through this client (Cognito's defaults otherwise). The list is
	// empty because Cognito rejects ALLOW_REFRESH_TOKEN_AUTH when refresh-token
	// rotation is enabled; rotation has its own refresh path.
	cfnClient.AddPropertyOverride(jsii.String("ExplicitAuthFlows"), []string{})
	// Rotate refresh tokens on use (Essentials tier), so an active connector
	// keeps renewing instead of hitting a fixed-lifetime cliff.
	cfnClient.AddPropertyOverride(jsii.String("RefreshTokenRotation"), map[string]any{
		"Feature": "ENABLED", "RetryGracePeriodSeconds": 60,
	})

	if userEmail != "" {
		// Transitional: the Step 0 user, retained so that dropping it from the
		// template (by deploying without -c userEmail) does not delete it.
		u := awscognito.NewCfnUserPoolUser(stack, jsii.String("TheUser"), &awscognito.CfnUserPoolUserProps{
			UserPoolId:             pool.UserPoolId(),
			Username:               jsii.String(userEmail),
			DesiredDeliveryMediums: &[]*string{jsii.String("EMAIL")},
			UserAttributes: &[]*awscognito.CfnUserPoolUser_AttributeTypeProperty{
				{Name: jsii.String("email"), Value: jsii.String(userEmail)},
				{Name: jsii.String("email_verified"), Value: jsii.String("true")},
			},
		})
		u.ApplyRemovalPolicy(awscdk.RemovalPolicy_RETAIN, nil)
	}

	issuer := fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s", region, *pool.UserPoolId())

	// ---- Lambda: least-privilege role, explicit log group ----------------
	logGroup := awslogs.NewLogGroup(stack, jsii.String("Logs"), &awslogs.LogGroupProps{
		LogGroupName:  jsii.String("/aws/lambda/skylight-mcp"),
		Retention:     awslogs.RetentionDays_ONE_MONTH,
		RemovalPolicy: awscdk.RemovalPolicy_DESTROY,
	})
	role := awsiam.NewRole(stack, jsii.String("FunctionRole"), &awsiam.RoleProps{
		AssumedBy: awsiam.NewServicePrincipal(jsii.String("lambda.amazonaws.com"), nil),
	})
	// Only its own log group, and only the two actions needed to write to it.
	role.AddToPolicy(awsiam.NewPolicyStatement(&awsiam.PolicyStatementProps{
		Actions:   &[]*string{jsii.String("logs:CreateLogStream"), jsii.String("logs:PutLogEvents")},
		Resources: &[]*string{logGroup.LogGroupArn()},
	}))

	env := map[string]*string{
		"AUTH_ISSUER":    jsii.String(issuer),
		"AUTH_CLIENT_ID": client.UserPoolClientId(),
		"AUTH_SCOPE":     jsii.String(resourceServerID + "/" + scopeName),
		// Cognito hosted-UI endpoints, advertised in the metadata the server serves.
		"AUTH_AUTHORIZE_URL": jsii.String(*domain.BaseUrl(nil) + "/oauth2/authorize"),
		"AUTH_TOKEN_URL":     jsii.String(*domain.BaseUrl(nil) + "/oauth2/token"),
	}
	if allowedSub != "" {
		env["AUTH_ALLOWED_SUB"] = jsii.String(allowedSub)
	}
	fn := awslambda.NewFunction(stack, jsii.String("Function"), &awslambda.FunctionProps{
		FunctionName: jsii.String("skylight-mcp"),
		Runtime:      awslambda.Runtime_PROVIDED_AL2023(),
		Architecture: awslambda.Architecture_ARM_64(),
		Handler:      jsii.String("bootstrap"),
		Code:         awslambda.Code_FromAsset(jsii.String("../dist/lambda"), nil),
		Role:         role,
		LogGroup:     logGroup,
		MemorySize:   jsii.Number(256),
		// Just under API Gateway's 30 s integration limit, leaving room for the
		// Skylight token refresh, its commit, and the API call (see PLAN §4).
		Timeout:     awscdk.Duration_Seconds(jsii.Number(28)),
		Environment: &env,
	})
	alias := awslambda.NewAlias(stack, jsii.String("LiveAlias"), &awslambda.AliasProps{
		AliasName: jsii.String("live"),
		Version:   fn.CurrentVersion(),
	})

	// ---- API Gateway HTTP API --------------------------------------------
	api := awsapigatewayv2.NewHttpApi(stack, jsii.String("Api"), &awsapigatewayv2.HttpApiProps{
		ApiName: jsii.String("skylight-mcp"),
	})
	connectorURL := jsii.String(*api.ApiEndpoint() + "/mcp")
	// claude.ai sends RFC 8707 "resource" = the connector URL, so Cognito binds
	// access tokens to it ("aud"). The Lambda requires that exact audience
	// whenever "aud" is present.
	fn.AddEnvironment(jsii.String("AUTH_AUDIENCE"), connectorURL, nil)
	integration := awsapigatewayv2integrations.NewHttpLambdaIntegration(jsii.String("Integration"), alias, nil)
	jwt := awsapigatewayv2authorizers.NewHttpJwtAuthorizer(jsii.String("Jwt"), jsii.String(issuer),
		&awsapigatewayv2authorizers.HttpJwtAuthorizerProps{
			// API Gateway checks "aud" when present, else "client_id". Resource-
			// bound tokens carry aud = connector URL; unbound ones only client_id.
			JwtAudience:    &[]*string{connectorURL, client.UserPoolClientId()},
			IdentitySource: &[]*string{jsii.String("$request.header.Authorization")},
		})
	// The MCP endpoint requires a valid token. GET/DELETE are routed too so the
	// (stateless) server can answer 405 rather than API Gateway answering 404.
	api.AddRoutes(&awsapigatewayv2.AddRoutesOptions{
		Path: jsii.String("/mcp"),
		Methods: &[]awsapigatewayv2.HttpMethod{
			awsapigatewayv2.HttpMethod_POST, awsapigatewayv2.HttpMethod_GET, awsapigatewayv2.HttpMethod_DELETE,
		},
		Integration: integration,
		Authorizer:  jwt,
	})
	// OAuth discovery must be reachable without a token.
	discovery := []string{
		"/.well-known/oauth-protected-resource",
		"/.well-known/oauth-protected-resource/mcp",
		"/.well-known/oauth-authorization-server",
		"/.well-known/oauth-authorization-server/mcp",
	}
	var discoveryRoutes []awsapigatewayv2.HttpRoute
	for _, p := range discovery {
		discoveryRoutes = append(discoveryRoutes, *api.AddRoutes(&awsapigatewayv2.AddRoutesOptions{
			Path:        jsii.String(p),
			Methods:     &[]awsapigatewayv2.HttpMethod{awsapigatewayv2.HttpMethod_GET},
			Integration: integration,
		})...)
	}
	// Single-user service: a low ceiling costs nothing and blunts abuse. The
	// unauthenticated discovery routes get an even lower one, because each
	// request invokes the Lambda (account concurrency limit is 10).
	stage := api.DefaultStage().Node().DefaultChild().(awsapigatewayv2.CfnStage)
	stage.SetDefaultRouteSettings(&awsapigatewayv2.CfnStage_RouteSettingsProperty{
		ThrottlingRateLimit:  jsii.Number(5),
		ThrottlingBurstLimit: jsii.Number(10),
	})
	perRoute := map[string]any{}
	for _, p := range discovery {
		perRoute["GET "+p] = map[string]any{"ThrottlingRateLimit": 1, "ThrottlingBurstLimit": 2}
	}
	stage.AddPropertyOverride(jsii.String("RouteSettings"), perRoute)
	// Route settings name routes by key, so the routes must exist first.
	for _, r := range discoveryRoutes {
		stage.Node().AddDependency(r)
	}
	// Gateway-level access log, so requests the gateway answers itself (404s,
	// authorizer 401s) are visible. Method, path, status and latency only: no
	// headers, query strings, IPs or tokens.
	apiLogs := awslogs.NewLogGroup(stack, jsii.String("ApiLogs"), &awslogs.LogGroupProps{
		LogGroupName:  jsii.String("/aws/apigateway/skylight-mcp"),
		Retention:     awslogs.RetentionDays_ONE_MONTH,
		RemovalPolicy: awscdk.RemovalPolicy_DESTROY,
	})
	stage.SetAccessLogSettings(&awsapigatewayv2.CfnStage_AccessLogSettingsProperty{
		DestinationArn: apiLogs.LogGroupArn(),
		Format: jsii.String(`{"requestId":"$context.requestId","time":"$context.requestTime","method":"$context.httpMethod",` +
			`"path":"$context.path","status":"$context.status","route":"$context.routeKey",` +
			`"authzError":"$context.authorizer.error","latencyMs":"$context.responseLatency"}`),
	})

	// ---- Outputs (no secrets) --------------------------------------------
	out := func(id string, v *string) {
		awscdk.NewCfnOutput(stack, jsii.String(id), &awscdk.CfnOutputProps{Value: v})
	}
	out("ConnectorUrl", jsii.String(*api.ApiEndpoint()+"/mcp"))
	out("ClientId", client.UserPoolClientId())
	out("UserPoolId", pool.UserPoolId())
	out("Issuer", jsii.String(issuer))
	out("HostedUiBase", domain.BaseUrl(nil))
	return stack
}

func main() {
	defer jsii.Close()
	app := awscdk.NewApp(nil)
	NewSkylightStack(app, "SkylightMcp", &awscdk.StackProps{
		Env: &awscdk.Environment{
			Account: jsii.String(os.Getenv("CDK_DEFAULT_ACCOUNT")),
			Region:  jsii.String(region),
		},
	})
	app.Synth(nil)
}
