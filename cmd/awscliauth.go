package cmd

import (
	"context"
	"fmt"
	"os"
	"path"
	"runtime"

	"github.com/DevLabFoundry/aws-cli-auth/internal/credentialexchange"
	"github.com/Ensono/eirctl/selfupdate"
	"github.com/spf13/cobra"
)

var (
	Version  string = "0.0.1"
	Revision string = "1111aaaa"
)

type Root struct {
	Cmd *cobra.Command
	// ChannelOut io.Writer
	// ChannelErr io.Writer
	// viperConf  *viper.Viper
	rootFlags *RootCmdFlags
	Datadir   string
}

type RootCmdFlags struct {
	CfgSectionName    string
	StoreInProfile    bool
	RoleChain         []string
	Verbose           bool
	Duration          int
	CustomIniLocation string
}

func New() *Root {
	rf := &RootCmdFlags{}
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

	r.Cmd.PersistentFlags().StringSliceVarP(&rf.RoleChain, "role-chain", "", []string{}, "If specified it will assume the roles from the base credentials, in order they are specified in")
	r.Cmd.PersistentFlags().BoolVarP(&rf.StoreInProfile, "store-profile", "s", false, `By default the credentials are returned to stdout to be used by the credential_process. 
	Set this flag to instead store the credentials under a named profile section. You can then reference that profile name via the CLI or for use in an SDK`)
	r.Cmd.PersistentFlags().StringVarP(&rf.CfgSectionName, "cfg-section", "", "", "Config section name to use in the look up of the config ini file (~/.aws-cli-auth.ini) and in the AWS credentials file")
	// When specifying store in profile the config section name must be provided
	r.Cmd.MarkFlagsRequiredTogether("store-profile", "cfg-section")
	r.Cmd.PersistentFlags().IntVarP(&rf.Duration, "max-duration", "d", 900, `Override default max session duration, in seconds, of the role session [900-43200]. 
NB: This cannot be higher than the 3600 as the API does not allow for AssumeRole for sessions longer than an hour`)
	r.Cmd.PersistentFlags().BoolVarP(&rf.Verbose, "verbose", "v", false, "Verbose output")
	r.Cmd.PersistentFlags().StringVarP(&rf.CustomIniLocation, "config-file", "c", "", "Specify the custom location of config file")

	_ = r.dataDirInit()
	return r
}

// SubCommands is a standalone Builder helper
//
// IF you are making your sub commands public, you can just pass them directly `WithSubCommands`
func SubCommands() []func(*Root) {
	suffix := fmt.Sprintf("aws-cli-auth-%s", runtime.GOOS)
	if runtime.GOOS == "windows" {
		suffix = suffix + "-" + runtime.GOARCH
	}

	uc := selfupdate.New("aws-cli-auth", "https://github.com/DevLabFoundry/aws-cli-auth/releases", selfupdate.WithDownloadSuffix(suffix))
	return []func(*Root){
		newSamlCmd,
		newClearCmd,
		newSpecificIdentityCmd,
		func(rootCmd *Root) {
			uc.AddToRootCommand(rootCmd.Cmd)
		},
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
