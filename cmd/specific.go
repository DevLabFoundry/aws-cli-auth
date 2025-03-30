package cmd

import (
	"fmt"
	"os/user"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/DevLabFoundry/aws-cli-auth/internal/credentialexchange"
	"github.com/spf13/cobra"
)

var (
	method      string
	SpecificCmd = &cobra.Command{
		Use:   "specific <flags>",
		Short: "Initiates a specific credential provider",
		Long: `Initiates a specific credential provider [WEB_ID] as opposed to relying on the defaultCredentialChain provider.
This is useful in CI situations where various authentication forms maybe present from AWS_ACCESS_KEY as env vars to metadata of the node.
Returns the same JSON object as the call to the AWS CLI for any of the sts AssumeRole* commands`,
		RunE: specific,
	}
)

func init() {
	SpecificCmd.PersistentFlags().StringVarP(&method, "method", "m", "WEB_ID", "Runs a specific credentialProvider as opposed to relying on the default chain provider fallback")
	SpecificCmd.PersistentFlags().StringVarP(&role, "role", "r", "", `Set the role you want to assume when SAML or OIDC process completes`)
	SpecificCmd.MarkPersistentFlagRequired("role")
	RootCmd.AddCommand(SpecificCmd)
}

func specific(cmd *cobra.Command, args []string) error {
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

	if method != "" {
		switch method {
		case "WEB_ID":
			awsCreds, err = credentialexchange.LoginAwsWebToken(ctx, user.Name, svc)
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported Method: %s", method)
		}
	}

	config := credentialexchange.CredentialConfig{
		BaseConfig: credentialexchange.BaseConfig{
			StoreInProfile: storeInProfile,
			Username:       user.Username,
			Role:           role,
			RoleChain:      credentialexchange.MergeRoleChain(role, roleChain, false),
		},
	}

	conf := credentialexchange.CredentialConfig{
		Duration: duration,
	}

	awsCreds, err = credentialexchange.AssumeRoleInChain(ctx, awsCreds, svc, config.BaseConfig.Username, config.BaseConfig.RoleChain, conf)
	if err != nil {
		return err
	}

	return credentialexchange.SetCredentials(awsCreds, config)
}
