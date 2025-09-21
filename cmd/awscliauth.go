package cmd

import (
	"context"
	"fmt"
	"os"
	"path"

	"github.com/DevLabFoundry/aws-cli-auth/internal/credentialexchange"
	"github.com/spf13/cobra"
)

var (
	Version  string = "0.0.1"
	Revision string = "1111aaaa"
)

type Root struct {
	ctx context.Context
	Cmd *cobra.Command
	// ChannelOut io.Writer
	// ChannelErr io.Writer
	// viperConf  *viper.Viper
	rootFlags *rootCmdFlags
	Datadir   string
}

type rootCmdFlags struct {
	cfgSectionName     string
	storeInProfile     bool
	killHangingProcess bool
	roleChain          []string
	verbose            bool
	duration           int
}

func New() *Root {
	rf := &rootCmdFlags{}
	r := &Root{
		rootFlags: rf,
		Cmd: &cobra.Command{
			Use:   "aws-cli-auth",
			Short: "CLI tool for retrieving AWS temporary credentials",
			Long: `CLI tool for retrieving AWS temporary credentials using SAML providers, or specified method of retrieval - i.e. force AWS_WEB_IDENTITY.
Useful in situations like CI jobs or containers where multiple env vars might be present.
Stores them under the $HOME/.aws/credentials file under a specified path or returns the crednetial_process payload for use in config`,
			Version:       fmt.Sprintf("%s-%s", Version, Revision),
			SilenceUsage:  true,
			SilenceErrors: true,
		},
	}

	r.Cmd.PersistentFlags().StringSliceVarP(&rf.roleChain, "role-chain", "", []string{}, "If specified it will assume the roles from the base credentials, in order they are specified in")
	r.Cmd.PersistentFlags().BoolVarP(&rf.storeInProfile, "store-profile", "s", false, `By default the credentials are returned to stdout to be used by the credential_process. 
	Set this flag to instead store the credentials under a named profile section. You can then reference that profile name via the CLI or for use in an SDK`)
	r.Cmd.PersistentFlags().StringVarP(&rf.cfgSectionName, "cfg-section", "", "", "Config section name in the default AWS credentials file. To enable priofi")
	// When specifying store in profile the config section name must be provided
	r.Cmd.MarkFlagsRequiredTogether("store-profile", "cfg-section")
	r.Cmd.PersistentFlags().IntVarP(&rf.duration, "max-duration", "d", 900, `Override default max session duration, in seconds, of the role session [900-43200]. 
NB: This cannot be higher than the 3600 as the API does not allow for AssumeRole for sessions longer than an hour`)
	r.Cmd.PersistentFlags().BoolVarP(&rf.verbose, "verbose", "v", false, "Verbose output")
	_ = r.dataDirInit()
	return r
}

// SubCommands is a standalone Builder helper
//
// IF you are making your sub commands public, you can just pass them directly `WithSubCommands`
func SubCommands() []func(*Root) {
	return []func(*Root){
		newSamlCmd,
		newClearCmd,
		newSpecificIdentityCmd,
	}
}

func (r *Root) WithSubCommands(iocFuncs ...func(rootCmd *Root)) {
	for _, fn := range iocFuncs {
		fn(r)
	}
}

func (r *Root) Execute(ctx context.Context) error {
	return r.Cmd.ExecuteContext(ctx)
}

func (r *Root) dataDirInit() error {
	datadir := path.Join(credentialexchange.HomeDir(), fmt.Sprintf(".%s-data", credentialexchange.SELF_NAME))
	if _, err := os.Stat(datadir); err != nil {
		return os.MkdirAll(datadir, 0755)
	}
	r.Datadir = datadir
	return nil
}
