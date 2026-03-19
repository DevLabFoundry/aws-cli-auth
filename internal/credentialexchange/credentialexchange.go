package credentialexchange

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
	"github.com/rs/zerolog"
)

var (
	ErrUnableAssume        = errors.New("unable to assume")
	ErrUnableSessionCreate = errors.New("unable to create a sesion")
	ErrTokenExpired        = errors.New("token expired")
	ErrMissingEnvVar       = errors.New("missing env var")
	ErrUnmarshalCred       = errors.New("unable to unmarshal credential from string")
)

type AuthSamlApi interface {
	AssumeRoleWithSAML(ctx context.Context, params *sts.AssumeRoleWithSAMLInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleWithSAMLOutput, error)
	GetCallerIdentity(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
	AssumeRole(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error)
}

type authWebTokenApi interface {
	AssumeRoleWithWebIdentity(ctx context.Context, params *sts.AssumeRoleWithWebIdentityInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error)
}

type iamSvcIface interface {
	authWebTokenApi
	AuthSamlApi
}

type CredentialExchange struct {
	logger zerolog.Logger
	svc    iamSvcIface
}

func New(logger zerolog.Logger, svc iamSvcIface) *CredentialExchange {
	return &CredentialExchange{
		logger: logger,
		svc:    svc,
	}
}

// LoginStsSaml exchanges saml response for STS creds
func (c *CredentialExchange) LoginStsSaml(ctx context.Context, samlResponse string, role AWSRole) (*AWSCredentials, error) {

	params := &sts.AssumeRoleWithSAMLInput{
		PrincipalArn:    aws.String(role.PrincipalARN), // Required
		RoleArn:         aws.String(role.RoleARN),      // Required
		SAMLAssertion:   aws.String(samlResponse),      // Required
		DurationSeconds: aws.Int32(int32(role.Duration)),
	}

	resp, err := c.svc.AssumeRoleWithSAML(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("%w, failed to retrieve STS credentials using SAML: %s", ErrUnableAssume, err.Error())
	}

	return &AWSCredentials{
		AWSAccessKey:    *resp.Credentials.AccessKeyId,
		AWSSecretKey:    *resp.Credentials.SecretAccessKey,
		AWSSessionToken: *resp.Credentials.SessionToken,
		PrincipalARN:    *resp.AssumedRoleUser.Arn,
		Expires:         resp.Credentials.Expiration.Local(),
	}, nil
}

// IsValid checks current credentials and
// returns them if they are still valid
// if reloadTimeBefore is less than time left on the creds
// then it will re-request a login
func (c *CredentialExchange) IsValid(ctx context.Context, currentCreds *AWSCredentials, reloadBeforeTime int) (bool, error) {
	if currentCreds == nil {
		return false, nil
	}

	if _, err := c.svc.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}, func(o *sts.Options) {
		// o.EndpointResolverV2 = &resolverProvider{} //.ResolveEndpoint(ctx, sts.EndpointParameters{})
		o.Credentials = &credsProvider{currentCreds.AWSAccessKey, currentCreds.AWSSecretKey, currentCreds.AWSSessionToken, currentCreds.Expires}
	}); err != nil {
		// var oe *smithy.OperationError
		var oe smithy.APIError
		if errors.As(err, &oe) {
			if oe.ErrorCode() == "ExpiredToken" || oe.ErrorCode() == "InvalidClientTokenId" {
				fmt.Fprintln(os.Stderr, "Stored Credentials invalid or expired")
				return false, nil
			}
		}
		return false, fmt.Errorf("the previous credential is invalid: %s, %w", err, ErrUnableAssume)
	}

	return !ReloadBeforeExpiry(currentCreds.Expires, reloadBeforeTime), nil
}

// LoginAwsWebToken
func (c *CredentialExchange) LoginAwsWebToken(ctx context.Context, username string) (*AWSCredentials, error) {
	// var role string
	r, exists := os.LookupEnv(AWS_ROLE_ARN)
	if !exists {
		return nil, fmt.Errorf("roleVar not found, %s is empty, %w", AWS_ROLE_ARN, ErrMissingEnvVar)
	}
	token, err := GetWebIdTokenFileContents()
	if err != nil {
		return nil, err
	}

	sessionName := SessionName(username, SELF_NAME)
	input := &sts.AssumeRoleWithWebIdentityInput{
		RoleArn:          &r,
		RoleSessionName:  &sessionName,
		WebIdentityToken: &token,
	}

	resp, err := c.svc.AssumeRoleWithWebIdentity(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve STS credentials using token file: %s, %w", err.Error(), ErrUnableAssume)
	}

	return &AWSCredentials{
		AWSAccessKey:    *resp.Credentials.AccessKeyId,
		AWSSecretKey:    *resp.Credentials.SecretAccessKey,
		AWSSessionToken: *resp.Credentials.SessionToken,
		PrincipalARN:    *resp.AssumedRoleUser.Arn,
		Expires:         resp.Credentials.Expiration.Local(),
	}, nil
}

// AssumeRoleInChain loops over all the roles provided
// If none are provided it will return the baseCreds
func (c *CredentialExchange) AssumeRoleInChain(ctx context.Context, baseCreds *AWSCredentials, username string, roles []string, conf CredentialConfig) (*AWSCredentials, error) {
	duration := int32(900)
	for idx, r := range roles {
		if len(roles) == idx+1 {
			duration = int32(conf.Duration)
		}
		c, err := c.assumeRoleWithCreds(ctx, baseCreds, username, r, duration)
		if err != nil {
			return nil, err
		}
		baseCreds = c
	}
	return baseCreds, nil
}

// AssumeRoleWithCreds uses existing creds retrieved from anywhere
// to pass to a credential provider and assume a specific role
//
// Most common use case is role chaining an WeBId role to a specific one
// duration is the
func (c *CredentialExchange) assumeRoleWithCreds(ctx context.Context, currentCreds *AWSCredentials, username, role string, duration int32) (*AWSCredentials, error) {

	timeNowPlusDuration := time.Now().Add(time.Duration(duration) * time.Second)

	input := &sts.AssumeRoleInput{
		RoleArn:         &role,
		RoleSessionName: aws.String(SessionName(username, SELF_NAME)),
		// DurationSeconds: &duration,
	}

	c.logger.Debug().Any("timeNowPlusDuration", timeNowPlusDuration).Msgf("")
	roleCreds, err := c.svc.AssumeRole(ctx, input, func(o *sts.Options) {
		o.Credentials = &credsProvider{currentCreds.AWSAccessKey, currentCreds.AWSSecretKey, currentCreds.AWSSessionToken, currentCreds.Expires}
	})

	if err != nil {
		return nil, fmt.Errorf("failed to retrieve STS credentials using Role Provided: %s, %w", err, ErrUnableAssume)
	}

	return &AWSCredentials{
		AWSAccessKey:    *roleCreds.Credentials.AccessKeyId,
		AWSSecretKey:    *roleCreds.Credentials.SecretAccessKey,
		AWSSessionToken: *roleCreds.Credentials.SessionToken,
		PrincipalARN:    *roleCreds.AssumedRoleUser.Arn,
		Expires:         timeNowPlusDuration.Local(),
	}, nil
}

type credsProvider struct {
	accessKey, secretKey, sessionToken string
	expiry                             time.Time
}

func (c *credsProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	return aws.Credentials{AccessKeyID: c.accessKey, SecretAccessKey: c.secretKey, SessionToken: c.sessionToken, CanExpire: true, Expires: c.expiry}, nil
}

// type resolverProvider struct {
// }

// func (c *resolverProvider) ResolveEndpoint(ctx context.Context, params sts.EndpointParameters) (transport.Endpoint, error) {
// 	return transport.Endpoint{}, nil
// }
