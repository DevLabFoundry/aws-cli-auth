package cmd

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path"
	"strings"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/DevLabFoundry/aws-cli-auth/internal/cmdutils"
	"github.com/DevLabFoundry/aws-cli-auth/internal/credentialexchange"
	"github.com/DevLabFoundry/aws-cli-auth/internal/web"
	"github.com/spf13/cobra"
)

var (
	ErrUnableToCreateSession = errors.New("sts - cannot start a new session")
)

const (
	UserEndpoint          = "https://portal.sso.%s.amazonaws.com/user"
	CredsEndpoint         = "https://portal.sso.%s.amazonaws.com/federation/credentials/"
	SsoCredsEndpointQuery = "?account_id=%s&role_name=%s&debug=true"
)

var (
	ssoRoleAccount, ssoRoleName string
)

var (
	providerUrl        string
	principalArn       string
	acsUrl             string
	isSso              bool
	ssoRegion          string
	ssoRole            string
	ssoUserEndpoint    string
	ssoFedCredEndpoint string
	datadir            string
	samlTimeout        int32
	reloadBeforeTime   int
	SamlCmd            = &cobra.Command{
		Use:   "saml <SAML ProviderUrl>",
		Short: "Get AWS credentials and out to stdout",
		Long:  `Get AWS credentials and out to stdout through your SAML provider authentication.`,
		RunE:  getSaml,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if reloadBeforeTime != 0 && reloadBeforeTime > duration {
				return fmt.Errorf("reload-before: %v, must be less than duration (-d): %v", reloadBeforeTime, duration)
			}
			if len(ssoRole) > 0 {
				sr := strings.Split(ssoRole, ":")
				if len(sr) != 2 {
					return fmt.Errorf("incorrectly formatted role for AWS SSO - must only be ACCOUNT:ROLE_NAME")
				}
				ssoRoleAccount, ssoRoleName = sr[0], sr[1]
			}
			return nil
		},
	}
)

func init() {
	cobra.OnInitialize(samlInitConfig)
	SamlCmd.PersistentFlags().StringVarP(&providerUrl, "provider", "p", "", `Saml Entity StartSSO Url.
This is the URL your Idp will make the first call to e.g.: https://company-xyz.okta.com/home/amazon_aws/12345SomeRandonId6789
`)
	SamlCmd.MarkPersistentFlagRequired("provider")
	SamlCmd.PersistentFlags().StringVarP(&principalArn, "principal", "", "", `Principal Arn of the SAML IdP in AWS
You should find it in the IAM portal e.g.: arn:aws:iam::1234567891012:saml-provider/MyCompany-Idp
`)
	// samlCmd.MarkPersistentFlagRequired("principal")
	SamlCmd.PersistentFlags().StringVarP(&role, "role", "r", "", `Set the role you want to assume when SAML or OIDC process completes`)
	SamlCmd.PersistentFlags().StringVarP(&acsUrl, "acsurl", "a", "https://signin.aws.amazon.com/saml", "Override the default ACS Url, used for checkin the post of the SAMLResponse")
	SamlCmd.PersistentFlags().StringVarP(&ssoUserEndpoint, "sso-user-endpoint", "", UserEndpoint, "UserEndpoint in a go style fmt.Sprintf string with a region placeholder")
	SamlCmd.PersistentFlags().StringVarP(&ssoRole, "sso-role", "", "", "Sso Role name must be in this format - 12345678910:PowerUser")
	SamlCmd.PersistentFlags().StringVarP(&ssoFedCredEndpoint, "sso-fed-endpoint", "", CredsEndpoint, "FederationCredEndpoint in a go style fmt.Sprintf string with a region placeholder")
	SamlCmd.PersistentFlags().StringVarP(&ssoRegion, "sso-region", "", "eu-west-1", "If using SSO, you must set the region")
	SamlCmd.PersistentFlags().BoolVarP(&isSso, "is-sso", "", false, `Enables the new AWS User portal login. 
If this flag is specified the --sso-role must also be specified.`)
	SamlCmd.PersistentFlags().IntVarP(&reloadBeforeTime, "reload-before", "", 0, "Triggers a credentials refresh before the specified max-duration. Value provided in seconds. Should be less than the max-duration of the session")
	//
	SamlCmd.MarkFlagsMutuallyExclusive("role", "sso-role")
	// samlCmd.MarkFlagsMutuallyExclusive("principal", "sso-role")
	// Non-SSO flow for SAML
	SamlCmd.MarkFlagsRequiredTogether("principal", "role")
	// SSO flow for SAML
	SamlCmd.MarkFlagsRequiredTogether("is-sso", "sso-role", "sso-region")
	SamlCmd.PersistentFlags().Int32VarP(&samlTimeout, "saml-timeout", "", 120, "Timeout in seconds, before the operation of waiting for a response is cancelled via the chrome driver")
	RootCmd.AddCommand(SamlCmd)
}

func getSaml(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	user, err := user.Current()
	if err != nil {
		return err
	}
	allRoles := credentialexchange.MergeRoleChain(role, roleChain, isSso)
	conf := credentialexchange.CredentialConfig{
		ProviderUrl:  providerUrl,
		PrincipalArn: principalArn,
		Duration:     duration,
		AcsUrl:       acsUrl,
		IsSso:        isSso,
		SsoRegion:    ssoRegion,
		SsoRole:      ssoRole,
		BaseConfig: credentialexchange.BaseConfig{
			StoreInProfile:       storeInProfile,
			Role:                 role,
			RoleChain:            allRoles,
			Username:             user.Username,
			CfgSectionName:       cfgSectionName,
			DoKillHangingProcess: killHangingProcess,
			ReloadBeforeTime:     reloadBeforeTime,
		},
	}

	saveRole := role
	if isSso {
		saveRole = ssoRole
		conf.SsoUserEndpoint = fmt.Sprintf(UserEndpoint, conf.SsoRegion)
		conf.SsoCredFedEndpoint = fmt.Sprintf(CredsEndpoint, conf.SsoRegion) + fmt.Sprintf(SsoCredsEndpointQuery, ssoRoleAccount, ssoRoleName)
	}

	datadir := path.Join(credentialexchange.HomeDir(), fmt.Sprintf(".%s-data", credentialexchange.SELF_NAME))
	os.MkdirAll(datadir, 0755)

	if len(allRoles) > 0 {
		saveRole = allRoles[len(allRoles)-1]
	}

	secretStore, err := credentialexchange.NewSecretStore(saveRole,
		fmt.Sprintf("%s-%s", credentialexchange.SELF_NAME, credentialexchange.RoleKeyConverter(saveRole)),
		os.TempDir(), user.Username)
	if err != nil {
		return err
	}

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return fmt.Errorf("failed to create session %s, %w", err, ErrUnableToCreateSession)
	}
	svc := sts.NewFromConfig(cfg)

	return cmdutils.GetCredsWebUI(ctx, svc, secretStore, conf, web.NewWebConf(datadir).WithTimeout(samlTimeout))
}

func samlInitConfig() {
	if _, err := os.Stat(credentialexchange.ConfigIniFile("")); err != nil {
		// creating a file
		rolesInit := []byte(fmt.Sprintf("[%s]\n", credentialexchange.INI_CONF_SECTION))
		err := os.WriteFile(credentialexchange.ConfigIniFile(""), rolesInit, 0644)
		cobra.CheckErr(err)
	}

	datadir = path.Join(credentialexchange.HomeDir(), fmt.Sprintf(".%s-data", credentialexchange.SELF_NAME))

	if _, err := os.Stat(datadir); err != nil {
		cobra.CheckErr(os.MkdirAll(datadir, 0755))
	}
}
