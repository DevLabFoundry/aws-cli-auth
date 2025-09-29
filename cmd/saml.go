package cmd

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"strings"

	"dario.cat/mergo"
	"github.com/DevLabFoundry/aws-cli-auth/internal/cmdutils"
	"github.com/DevLabFoundry/aws-cli-auth/internal/credentialexchange"
	"github.com/DevLabFoundry/aws-cli-auth/internal/web"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/spf13/cobra"
	"gopkg.in/ini.v1"
)

var (
	ErrUnableToCreateSession = errors.New("sts - cannot start a new session")
)

const (
	UserEndpoint          = "https://portal.sso.%s.amazonaws.com/user"
	CredsEndpoint         = "https://portal.sso.%s.amazonaws.com/federation/credentials/"
	SsoCredsEndpointQuery = "?account_id=%s&role_name=%s&debug=true"
)

type SamlCmdFlags struct {
	ProviderUrl          string
	PrincipalArn         string
	AcsUrl               string
	IsSso                bool
	Role                 string
	SsoRegion            string
	SsoRole              string
	SsoUserEndpoint      string
	SsoFedCredEndpoint   string
	CustomExecutablePath string
	SamlTimeout          int32
	ReloadBeforeTime     int
}

type samlCmd struct {
	flags                       *SamlCmdFlags
	ssoRoleAccount, ssoRoleName string
	cmd                         *cobra.Command
}

func newSamlCmd(r *Root) {
	flags := &SamlCmdFlags{}
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

			iniFile, err := samlInitConfig(r.rootFlags.CustomIniLocation)
			if err != nil {
				return err
			}

			conf, err := credentialexchange.LoadCliConfig(iniFile, r.rootFlags.CfgSectionName)
			if err != nil {
				return err
			}

			if err := ConfigFromFlags(conf, r.rootFlags, flags, user.Username); err != nil {
				return err
			}

			// now we want to overwrite anything set via the command line
			saveRole := flags.Role
			if flags.IsSso {
				saveRole = flags.SsoRole
				conf.SsoUserEndpoint = fmt.Sprintf(UserEndpoint, conf.SsoRegion)
				conf.SsoCredFedEndpoint = fmt.Sprintf(
					CredsEndpoint, conf.SsoRegion) + fmt.Sprintf(
					SsoCredsEndpointQuery, sc.ssoRoleAccount, sc.ssoRoleName)
			}

			allRoles := credentialexchange.MergeRoleChain(conf.BaseConfig.Role, conf.BaseConfig.RoleChain, flags.IsSso)

			if len(allRoles) > 0 {
				saveRole = allRoles[len(allRoles)-1]
			}

			secretStore, err := credentialexchange.NewSecretStore(saveRole,
				fmt.Sprintf("%s-%s", credentialexchange.SELF_NAME, credentialexchange.RoleKeyConverter(saveRole)),
				os.TempDir(), user.Username)
			if err != nil {
				return err
			}

			// we want to remove any AWS_* env vars that could interfere with the default config
			// for _, envVar := range []string{"AWS_PROFILE", "AWS_ACCESS_KEY_ID",
			// 	"AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"} {
			// 	os.Unsetenv(envVar)
			// }

			awsConf, err := config.LoadDefaultConfig(ctx)
			if err != nil {
				return fmt.Errorf("failed to create session %s, %w", err, ErrUnableToCreateSession)
			}

			svc := sts.NewFromConfig(awsConf)
			webConfig := web.NewWebConf(r.Datadir).
				WithTimeout(flags.SamlTimeout).
				WithCustomExecutable(conf.BaseConfig.BrowserExecutablePath)

			return cmdutils.GetCredsWebUI(ctx, svc, secretStore, *conf, webConfig)

		},
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if flags.ReloadBeforeTime != 0 && flags.ReloadBeforeTime > r.rootFlags.Duration {
				return fmt.Errorf("reload-before: %v, must be less than duration (-d): %v", flags.ReloadBeforeTime, r.rootFlags.Duration)
			}
			if len(flags.SsoRole) > 0 {
				sr := strings.Split(flags.SsoRole, ":")
				if len(sr) != 2 {
					return fmt.Errorf("incorrectly formatted role for AWS SSO - must only be ACCOUNT:ROLE_NAME")
				}
				sc.ssoRoleAccount, sc.ssoRoleName = sr[0], sr[1]
			}
			return nil
		},
	}

	sc.cmd.PersistentFlags().StringVarP(&flags.ProviderUrl, "provider", "p", "", `Saml Entity StartSSO Url.
This is the URL your Idp will make the first call to e.g.: https://company-xyz.okta.com/home/amazon_aws/12345SomeRandonId6789
`)
	// _ = sc.cmd.MarkPersistentFlagRequired("provider")
	sc.cmd.PersistentFlags().StringVarP(&flags.PrincipalArn, "principal", "", "", `Principal Arn of the SAML IdP in AWS
You should find it in the IAM portal e.g.: arn:aws:iam::1234567891012:saml-provider/MyCompany-Idp
`)
	// samlCmd.MarkPersistentFlagRequired("principal")
	sc.cmd.PersistentFlags().StringVarP(&flags.Role, "role", "r", "", `Set the role you want to assume when SAML or OIDC process completes`)
	sc.cmd.PersistentFlags().StringVarP(&flags.AcsUrl, "acsurl", "a", "https://signin.aws.amazon.com/saml", "Override the default ACS Url, used for checkin the post of the SAMLResponse")
	sc.cmd.PersistentFlags().StringVarP(&flags.SsoUserEndpoint, "sso-user-endpoint", "", UserEndpoint, "UserEndpoint in a go style fmt.Sprintf string with a region placeholder")
	sc.cmd.PersistentFlags().StringVarP(&flags.SsoRole, "sso-role", "", "", "Sso Role name must be in this format - 12345678910:PowerUser")
	sc.cmd.PersistentFlags().StringVarP(&flags.SsoFedCredEndpoint, "sso-fed-endpoint", "", CredsEndpoint, "FederationCredEndpoint in a go style fmt.Sprintf string with a region placeholder")
	sc.cmd.PersistentFlags().StringVarP(&flags.SsoRegion, "sso-region", "", "eu-west-1", "If using SSO, you must set the region")
	sc.cmd.PersistentFlags().StringVarP(&flags.CustomExecutablePath, "executable-path", "", "", `Custom path to an executable

This needs to be a chromium like executable - e.g. Chrome, Chromium, Brave, Edge. 

You can find out the path by opening your browser and typing in chrome|brave|edge://version
`)
	sc.cmd.PersistentFlags().BoolVarP(&flags.IsSso, "is-sso", "", false, `Enables the new AWS User portal login. 
If this flag is specified the --sso-role must also be specified.`)
	sc.cmd.PersistentFlags().IntVarP(&flags.ReloadBeforeTime, "reload-before", "", 0, "Triggers a credentials refresh before the specified max-duration. Value provided in seconds. Should be less than the max-duration of the session")
	//
	sc.cmd.MarkFlagsMutuallyExclusive("role", "sso-role")
	// Non-SSO flow for SAML
	// sc.cmd.MarkFlagsRequiredTogether("principal", "role")
	// SSO flow for SAML
	sc.cmd.MarkFlagsRequiredTogether("is-sso", "sso-role", "sso-region")
	sc.cmd.PersistentFlags().Int32VarP(&flags.SamlTimeout, "saml-timeout", "", 120, "Timeout in seconds, before the operation of waiting for a response is cancelled via the chrome driver")
	// Add subcommand to root command
	r.Cmd.AddCommand(sc.cmd)
}

func samlInitConfig(customPath string) (*ini.File, error) {
	configPath := credentialexchange.ConfigIniFile(customPath)
	if _, err := os.Stat(configPath); err != nil {
		// creating a file
		rolesInit := []byte(fmt.Sprintf("; aws-cli-auth generated [role] section\n[%s]\n", credentialexchange.INI_CONF_SECTION))
		if err := os.WriteFile(configPath, rolesInit, 0644); err != nil {
			return nil, err
		}
	}
	return ini.Load(configPath)
}

func ConfigFromFlags(fileConfig *credentialexchange.CredentialConfig, rf *RootCmdFlags, sf *SamlCmdFlags, user string) error {
	d := fileConfig.Duration
	// 900 is the default
	if rf.Duration != 900 {
		d = rf.Duration
	}
	flagSamlConf := &credentialexchange.CredentialConfig{
		ProviderUrl:  sf.ProviderUrl,
		PrincipalArn: sf.PrincipalArn,
		Duration:     d,
		AcsUrl:       sf.AcsUrl,
		IsSso:        sf.IsSso,
		SsoRegion:    sf.SsoRegion,
		SsoRole:      sf.SsoRole,
	}

	flagBaseConfig := &credentialexchange.BaseConfig{
		StoreInProfile: rf.StoreInProfile,
		Role:           sf.Role,
		// RoleChain is added in the command function
		RoleChain:        rf.RoleChain,
		Username:         user,
		CfgSectionName:   rf.CfgSectionName,
		ReloadBeforeTime: sf.ReloadBeforeTime,
	}

	if err := mergo.Merge(&fileConfig.BaseConfig, flagBaseConfig, mergo.WithOverride); err != nil {
		return err
	}

	baseConf := fileConfig.BaseConfig
	if err := mergo.Merge(fileConfig, flagSamlConf, mergo.WithOverride, mergo.WithOverrideEmptySlice); err != nil {
		return err
	}

	fileConfig.BaseConfig = baseConf
	fileConfig.Duration = d
	return nil
}
