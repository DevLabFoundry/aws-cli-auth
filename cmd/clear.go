package cmd

import (
	"fmt"
	"os"
	"os/user"

	"github.com/DevLabFoundry/aws-cli-auth/internal/credentialexchange"
	"github.com/DevLabFoundry/aws-cli-auth/internal/web"
	"github.com/spf13/cobra"
)

type clearFlags struct {
	force bool
}

func newClearCmd(r *Root) {
	flags := &clearFlags{}

	cmd := &cobra.Command{
		Use:   "clear-cache <flags>",
		Short: "Clears any stored credentials in the OS secret store",
		RunE: func(cmd *cobra.Command, args []string) error {
			user, err := user.Current()
			if err != nil {
				return err
			}
			if err := samlInitConfig(); err != nil {
				return err
			}
			secretStore, err := credentialexchange.NewSecretStore("",
				fmt.Sprintf("%s-%s", credentialexchange.SELF_NAME, credentialexchange.RoleKeyConverter("")),
				os.TempDir(), user.Username)

			if err != nil {
				return err
			}

			if flags.force {
				w := &web.Web{}
				if err := w.ForceKill(r.Datadir); err != nil {
					return err
				}
				fmt.Fprint(os.Stderr, "Chromium Cache cleared")
			}

			if err := secretStore.ClearAll(); err != nil {
				fmt.Fprint(os.Stderr, err.Error())
			}

			if err := os.Remove(credentialexchange.ConfigIniFile("")); err != nil {
				return err
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
