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

const region = "us-east-2"

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

	userEmail := ctxString(stack, "userEmail")
	if userEmail == "" {
		panic("missing context: pass -c userEmail=<address>")
	}
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
	sum := sha256.Sum256([]byte(os.Getenv("CDK_DEFAULT_ACCOUNT") + "skylight-mcp"))
	domain := pool.AddDomain(jsii.String("Domain"), &awscognito.UserPoolDomainOptions{
		CognitoDomain: &awscognito.CognitoDomainOptions{
			DomainPrefix: jsii.String("skylight-mcp-" + hex.EncodeToString(sum[:])[:10]),
		},
	})

	client := pool.AddClient(jsii.String("ConnectorClient"), &awscognito.UserPoolClientOptions{
		UserPoolClientName: jsii.String("claude-connector"),
		GenerateSecret:     jsii.Bool(true),
		OAuth: &awscognito.OAuthSettings{
			Flows:        &awscognito.OAuthFlows{AuthorizationCodeGrant: jsii.Bool(true)},
			Scopes:       &[]awscognito.OAuthScope{awscognito.OAuthScope_OPENID(), awscognito.OAuthScope_EMAIL()},
			CallbackUrls: &callbackURLs,
		},
		SupportedIdentityProviders: &[]awscognito.UserPoolClientIdentityProvider{awscognito.UserPoolClientIdentityProvider_COGNITO()},
		AccessTokenValidity:        awscdk.Duration_Hours(jsii.Number(1)),
		IdTokenValidity:            awscdk.Duration_Hours(jsii.Number(1)),
		RefreshTokenValidity:       awscdk.Duration_Days(jsii.Number(30)),
		EnableTokenRevocation:      jsii.Bool(true),
		PreventUserExistenceErrors: jsii.Bool(true),
	})

	awscognito.NewCfnUserPoolUser(stack, jsii.String("TheUser"), &awscognito.CfnUserPoolUserProps{
		UserPoolId:             pool.UserPoolId(),
		Username:               jsii.String(userEmail),
		DesiredDeliveryMediums: &[]*string{jsii.String("EMAIL")},
		UserAttributes: &[]*awscognito.CfnUserPoolUser_AttributeTypeProperty{
			{Name: jsii.String("email"), Value: jsii.String(userEmail)},
			{Name: jsii.String("email_verified"), Value: jsii.String("true")},
		},
	})

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
		Timeout:      awscdk.Duration_Seconds(jsii.Number(10)),
		Environment:  &env,
	})
	alias := awslambda.NewAlias(stack, jsii.String("LiveAlias"), &awslambda.AliasProps{
		AliasName: jsii.String("live"),
		Version:   fn.CurrentVersion(),
	})

	// ---- API Gateway HTTP API --------------------------------------------
	api := awsapigatewayv2.NewHttpApi(stack, jsii.String("Api"), &awsapigatewayv2.HttpApiProps{
		ApiName: jsii.String("skylight-mcp"),
	})
	integration := awsapigatewayv2integrations.NewHttpLambdaIntegration(jsii.String("Integration"), alias, nil)
	jwt := awsapigatewayv2authorizers.NewHttpJwtAuthorizer(jsii.String("Jwt"), jsii.String(issuer),
		&awsapigatewayv2authorizers.HttpJwtAuthorizerProps{
			JwtAudience:    &[]*string{client.UserPoolClientId()},
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
	for _, p := range []string{
		"/.well-known/oauth-protected-resource",
		"/.well-known/oauth-protected-resource/mcp",
		"/.well-known/oauth-authorization-server",
		"/.well-known/oauth-authorization-server/mcp",
		"/.well-known/openid-configuration",
		"/.well-known/openid-configuration/mcp",
	} {
		api.AddRoutes(&awsapigatewayv2.AddRoutesOptions{
			Path:        jsii.String(p),
			Methods:     &[]awsapigatewayv2.HttpMethod{awsapigatewayv2.HttpMethod_GET},
			Integration: integration,
		})
	}
	// Single-user service: a low ceiling costs nothing and blunts abuse.
	stage := api.DefaultStage().Node().DefaultChild().(awsapigatewayv2.CfnStage)
	stage.SetDefaultRouteSettings(&awsapigatewayv2.CfnStage_RouteSettingsProperty{
		ThrottlingRateLimit:  jsii.Number(5),
		ThrottlingBurstLimit: jsii.Number(10),
	})
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
