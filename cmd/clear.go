package cmd

import (
	"errors"
	"fmt"
	"os"
	"os/user"

	"github.com/DevLabFoundry/aws-cli-auth/internal/credentialexchange"
	"github.com/spf13/cobra"
)

type clearFlags struct {
	force bool
}

var (
	ErrCannotReadConfig = errors.New("cannot open config file")
)

func newClearCmd(r *Root) {
	flags := &clearFlags{}

	cmd := &cobra.Command{
		Use:   "clear-cache <flags>",
		Short: "Clears any stored credentials in the OS secret store",
		Long: `Clears any stored credentials in the OS secret store
		NB: Occassionally you may encounter a hanging chromium processes, you should kill all the instances of the chromium (or if using own browser binary) PIDs`,
		RunE: func(cmd *cobra.Command, args []string) error {
			user, err := user.Current()
			if err != nil {
				return err
			}
			iniCfg, err := samlInitConfig(r.rootFlags.CustomIniLocation)
			if err != nil {
				return err
			}
			secretStore, err := credentialexchange.NewSecretStore("",
				fmt.Sprintf("%s-%s", credentialexchange.SELF_NAME, credentialexchange.RoleKeyConverter("")),
				os.TempDir(), user.Username)

			if err != nil {
				return err
			}

			if flags.force {
				fmt.Fprint(cmd.OutOrStderr(), "delete ~/.aws-cli-auth-data/ manually")
			}

			if err := secretStore.ClearAll(iniCfg); err != nil {
				fmt.Fprint(cmd.OutOrStderr(), err.Error())
			}

			return nil
		},
	}

	cmd.PersistentFlags().BoolVarP(&flags.force, "force", "f", false, `If aws-cli-auth exited improprely in a previous run there is a chance that there could be hanging processes left over.

This will forcefully all chromium processes.

If you are on a windows machine and also use chrome as your current/main browser this will also kill those processes. 

Use with caution.

If for any reason the local ini file and the secret store on your OS (keyring on GNU, keychain MacOS, windows secret store) are out of sync and the secrets cannot be retrieved by name but still exists,
you might want to use CLI or GUI interface to the secret backing store on your OS and search for a secret prefixed with aws-cli-* and delete manually
`)
	r.Cmd.AddCommand(cmd)
}
