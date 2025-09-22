package cmd

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"strings"

	"github.com/DevLabFoundry/aws-cli-auth/internal/cmdutils"
	"github.com/DevLabFoundry/aws-cli-auth/internal/credentialexchange"
	"github.com/DevLabFoundry/aws-cli-auth/internal/web"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
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

type samlFlags struct {
	providerUrl          string
	principalArn         string
	acsUrl               string
	isSso                bool
	role                 string
	ssoRegion            string
	ssoRole              string
	ssoUserEndpoint      string
	ssoFedCredEndpoint   string
	customExecutablePath string
	samlTimeout          int32
	reloadBeforeTime     int
}

type samlCmd struct {
	flags                       *samlFlags
	ssoRoleAccount, ssoRoleName string
	cmd                         *cobra.Command
}

func newSamlCmd(r *Root) {
	flags := &samlFlags{}
	sc := &samlCmd{
		flags: flags,
	}

	sc.cmd = &cobra.Command{
		Use:   "saml <SAML ProviderUrl>",
		Short: "Get AWS credentials and out to stdout",
		Long:  `Get AWS credentials and out to stdout through your SAML provider authentication.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			user, err := user.Current()
			if err != nil {
				return err
			}

			if err := samlInitConfig(); err != nil {
				return err
			}

			allRoles := credentialexchange.MergeRoleChain(flags.role, r.rootFlags.roleChain, sc.flags.isSso)
			conf := credentialexchange.CredentialConfig{
				ProviderUrl:  flags.providerUrl,
				PrincipalArn: flags.principalArn,
				Duration:     r.rootFlags.duration,
				AcsUrl:       flags.acsUrl,
				IsSso:        flags.isSso,
				SsoRegion:    flags.ssoRegion,
				SsoRole:      flags.ssoRole,
				BaseConfig: credentialexchange.BaseConfig{
					StoreInProfile:       r.rootFlags.storeInProfile,
					Role:                 flags.role,
					RoleChain:            allRoles,
					Username:             user.Username,
					CfgSectionName:       r.rootFlags.cfgSectionName,
					DoKillHangingProcess: r.rootFlags.killHangingProcess,
					ReloadBeforeTime:     flags.reloadBeforeTime,
				},
			}

			saveRole := flags.role
			if flags.isSso {
				saveRole = flags.ssoRole
				conf.SsoUserEndpoint = fmt.Sprintf(UserEndpoint, conf.SsoRegion)
				conf.SsoCredFedEndpoint = fmt.Sprintf(
					CredsEndpoint, conf.SsoRegion) + fmt.Sprintf(
					SsoCredsEndpointQuery, sc.ssoRoleAccount, sc.ssoRoleName)
			}

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
			webConfig := web.NewWebConf(r.Datadir).WithTimeout(flags.samlTimeout)
			webConfig.CustomChromeExecutable = flags.customExecutablePath
			return cmdutils.GetCredsWebUI(ctx, svc, secretStore, conf, webConfig)
		},
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if flags.reloadBeforeTime != 0 && flags.reloadBeforeTime > r.rootFlags.duration {
				return fmt.Errorf("reload-before: %v, must be less than duration (-d): %v", flags.reloadBeforeTime, r.rootFlags.duration)
			}
			if len(flags.ssoRole) > 0 {
				sr := strings.Split(flags.ssoRole, ":")
				if len(sr) != 2 {
					return fmt.Errorf("incorrectly formatted role for AWS SSO - must only be ACCOUNT:ROLE_NAME")
				}
				sc.ssoRoleAccount, sc.ssoRoleName = sr[0], sr[1]
			}
			return nil
		},
	}

	sc.cmd.PersistentFlags().StringVarP(&flags.providerUrl, "provider", "p", "", `Saml Entity StartSSO Url.
This is the URL your Idp will make the first call to e.g.: https://company-xyz.okta.com/home/amazon_aws/12345SomeRandonId6789
`)
	_ = sc.cmd.MarkPersistentFlagRequired("provider")
	sc.cmd.PersistentFlags().StringVarP(&flags.principalArn, "principal", "", "", `Principal Arn of the SAML IdP in AWS
You should find it in the IAM portal e.g.: arn:aws:iam::1234567891012:saml-provider/MyCompany-Idp
`)
	// samlCmd.MarkPersistentFlagRequired("principal")
	sc.cmd.PersistentFlags().StringVarP(&flags.role, "role", "r", "", `Set the role you want to assume when SAML or OIDC process completes`)
	sc.cmd.PersistentFlags().StringVarP(&flags.acsUrl, "acsurl", "a", "https://signin.aws.amazon.com/saml", "Override the default ACS Url, used for checkin the post of the SAMLResponse")
	sc.cmd.PersistentFlags().StringVarP(&flags.ssoUserEndpoint, "sso-user-endpoint", "", UserEndpoint, "UserEndpoint in a go style fmt.Sprintf string with a region placeholder")
	sc.cmd.PersistentFlags().StringVarP(&flags.ssoRole, "sso-role", "", "", "Sso Role name must be in this format - 12345678910:PowerUser")
	sc.cmd.PersistentFlags().StringVarP(&flags.ssoFedCredEndpoint, "sso-fed-endpoint", "", CredsEndpoint, "FederationCredEndpoint in a go style fmt.Sprintf string with a region placeholder")
	sc.cmd.PersistentFlags().StringVarP(&flags.ssoRegion, "sso-region", "", "eu-west-1", "If using SSO, you must set the region")
	sc.cmd.PersistentFlags().StringVarP(&flags.customExecutablePath, "executable-path", "", "", `Custom path to an executable

This needs to be a chromium like executable - e.g. Chrome, Chromium, Brave, Edge. 

You can find out the path by opening your browser and typing in chrome|brave|edge://version
`)
	sc.cmd.PersistentFlags().BoolVarP(&flags.isSso, "is-sso", "", false, `Enables the new AWS User portal login. 
If this flag is specified the --sso-role must also be specified.`)
	sc.cmd.PersistentFlags().IntVarP(&flags.reloadBeforeTime, "reload-before", "", 0, "Triggers a credentials refresh before the specified max-duration. Value provided in seconds. Should be less than the max-duration of the session")
	//
	sc.cmd.MarkFlagsMutuallyExclusive("role", "sso-role")
	// samlCmd.MarkFlagsMutuallyExclusive("principal", "sso-role")
	// Non-SSO flow for SAML
	sc.cmd.MarkFlagsRequiredTogether("principal", "role")
	// SSO flow for SAML
	sc.cmd.MarkFlagsRequiredTogether("is-sso", "sso-role", "sso-region")
	sc.cmd.PersistentFlags().Int32VarP(&flags.samlTimeout, "saml-timeout", "", 120, "Timeout in seconds, before the operation of waiting for a response is cancelled via the chrome driver")
	// Add subcommand to root command
	r.Cmd.AddCommand(sc.cmd)

}

func samlInitConfig() error {
	if _, err := os.Stat(credentialexchange.ConfigIniFile("")); err != nil {
		// creating a file
		rolesInit := []byte(fmt.Sprintf("[%s]\n", credentialexchange.INI_CONF_SECTION))
		return os.WriteFile(credentialexchange.ConfigIniFile(""), rolesInit, 0644)
	}
	return nil
}
