package cmdutils

import (
	"context"
	"errors"
	"fmt"

	"github.com/DevLabFoundry/aws-cli-auth/internal/credentialexchange"
	"github.com/DevLabFoundry/aws-cli-auth/internal/web"
)

var (
	ErrMissingArg       = errors.New("missing arg")
	ErrUnableToValidate = errors.New("unable to validate token")
)

type SecretStorageImpl interface {
	AWSCredential() (*credentialexchange.AWSCredentials, error)
	Clear() error
	ClearAll() error
	SaveAWSCredential(cred *credentialexchange.AWSCredentials) error
}

// GetCredsWebUI
func GetCredsWebUI(ctx context.Context, svc credentialexchange.AuthSamlApi, secretStore SecretStorageImpl, conf credentialexchange.CredentialConfig, webConfig *web.WebConfig) error {
	if conf.BaseConfig.CfgSectionName == "" && conf.BaseConfig.StoreInProfile {
		return fmt.Errorf("Config-Section name must be provided if store-profile is enabled %w", ErrMissingArg)
	}

	// Try to reuse stored credential in secret
	storedCreds, err := secretStore.AWSCredential()
	if err != nil {
		return err
	}

	credsValid, err := credentialexchange.IsValid(ctx, storedCreds, conf.BaseConfig.ReloadBeforeTime, svc)
	if err != nil {
		return fmt.Errorf("failed to validate: %s, %w", err, ErrUnableToValidate)
	}

	if !credsValid {
		// TODO: delete from keychain first
		if conf.IsSso {
			return refreshAwsSsoCreds(ctx, conf, secretStore, svc, webConfig)
		}
		return refreshSamlCreds(ctx, conf, secretStore, svc, webConfig)
	}

	return credentialexchange.SetCredentials(storedCreds, conf)
}

// refreshAwsSsoCreds uses the temp user credentials returned via AWS SSO,
// upon successful auth from the IDP.
// Once credentials are captured they are used in the role assumption process.
func refreshAwsSsoCreds(ctx context.Context, conf credentialexchange.CredentialConfig, secretStore SecretStorageImpl, svc credentialexchange.AuthSamlApi, webConfig *web.WebConfig) error {
	webBrowser := web.New(webConfig)
	capturedCreds, err := webBrowser.GetSSOCredentials(conf)
	if err != nil {
		return err
	}
	awsCreds := &credentialexchange.AWSCredentials{}
	awsCreds.FromRoleCredString(capturedCreds)
	return completeCredProcess(ctx, secretStore, svc, awsCreds, conf)
}

func refreshSamlCreds(ctx context.Context, conf credentialexchange.CredentialConfig, secretStore SecretStorageImpl, svc credentialexchange.AuthSamlApi, webConfig *web.WebConfig) error {

	webBrowser := web.New(webConfig)

	duration := conf.Duration

	samlResp, err := webBrowser.GetSamlLogin(conf)
	if err != nil {
		return err
	}

	// If there are additional roles to chain from
	// set the duration to 900 seconds
	// and respect the user provided value
	// when applying the assuming the last role
	if len(conf.BaseConfig.RoleChain) > 0 {
		duration = 900
	}

	roleObj := credentialexchange.AWSRole{
		RoleARN:      conf.BaseConfig.Role,
		PrincipalARN: conf.PrincipalArn,
		Name:         credentialexchange.SessionName(conf.BaseConfig.Username, credentialexchange.SELF_NAME),
		Duration:     duration,
	}

	awsCreds, err := credentialexchange.LoginStsSaml(ctx, samlResp, roleObj, svc)
	if err != nil {
		return err
	}
	return completeCredProcess(ctx, secretStore, svc, awsCreds, conf)
}

func completeCredProcess(ctx context.Context, secretStore SecretStorageImpl, svc credentialexchange.AuthSamlApi, awsCreds *credentialexchange.AWSCredentials, conf credentialexchange.CredentialConfig) error {
	creds, err := credentialexchange.AssumeRoleInChain(ctx, awsCreds, svc, conf.BaseConfig.Username, conf.BaseConfig.RoleChain, conf)
	if err != nil {
		return err
	}
	creds.Version = 1

	if err := secretStore.SaveAWSCredential(creds); err != nil {
		return err
	}

	return credentialexchange.SetCredentials(creds, conf)
}
