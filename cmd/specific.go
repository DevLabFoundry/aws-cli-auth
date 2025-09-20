package cmd

import (
	"fmt"
	"os/user"

	"github.com/DevLabFoundry/aws-cli-auth/internal/credentialexchange"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/spf13/cobra"
)

type specificCmdFlags struct {
	method string
	role   string
}

func newSpecificIdentityCmd(r *Root) {
	flags := &specificCmdFlags{}
	cmd := &cobra.Command{
		Use:   "specific <flags>",
		Short: "Initiates a specific credential provider",
		Long: `Initiates a specific credential provider [WEB_ID] as opposed to relying on the defaultCredentialChain provider.
This is useful in CI situations where various authentication forms maybe present from AWS_ACCESS_KEY as env vars to metadata of the node.
Returns the same JSON object as the call to the AWS CLI for any of the sts AssumeRole* commands`,
		RunE: func(cmd *cobra.Command, args []string) error {
			var awsCreds *credentialexchange.AWSCredentials
			ctx := cmd.Context()

			cfg, err := config.LoadDefaultConfig(ctx)
			if err != nil {
				return fmt.Errorf("failed to create session %s, %w", err, ErrUnableToCreateSession)
			}
			svc := sts.NewFromConfig(cfg)

			user, err := user.Current()

			if err != nil {
				return err
			}

			if flags.method != "" {
				switch flags.method {
				case "WEB_ID":
					awsCreds, err = credentialexchange.LoginAwsWebToken(ctx, user.Name, svc)
					if err != nil {
						return err
					}
				default:
					return fmt.Errorf("unsupported Method: %s", flags.method)
				}
			}

			config := credentialexchange.CredentialConfig{
				BaseConfig: credentialexchange.BaseConfig{
					StoreInProfile: r.rootFlags.storeInProfile,
					Username:       user.Username,
					Role:           flags.role,
					RoleChain:      credentialexchange.MergeRoleChain(flags.role, r.rootFlags.roleChain, false),
				},
			}

			conf := credentialexchange.CredentialConfig{
				Duration: r.rootFlags.duration,
			}

			awsCreds, err = credentialexchange.AssumeRoleInChain(ctx, awsCreds, svc, config.BaseConfig.Username, config.BaseConfig.RoleChain, conf)
			if err != nil {
				return err
			}

			return credentialexchange.SetCredentials(awsCreds, config)
		},
	}

	cmd.PersistentFlags().StringVarP(&flags.method, "method", "m", "WEB_ID", "Runs a specific credentialProvider as opposed to relying on the default chain provider fallback")
	cmd.PersistentFlags().StringVarP(&flags.role, "role", "r", "", `Set the role you want to assume when SAML or OIDC process completes`)
	cmd.MarkPersistentFlagRequired("role")
	r.Cmd.AddCommand(cmd)
}
