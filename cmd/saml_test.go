package cmd_test

import (
	"testing"

	"github.com/DevLabFoundry/aws-cli-auth/cmd"
	"github.com/DevLabFoundry/aws-cli-auth/internal/credentialexchange"
	"github.com/go-test/deep"
)

func Test_ConfigMerge(t *testing.T) {
	conf := &credentialexchange.CredentialConfig{
		BaseConfig: credentialexchange.BaseConfig{
			BrowserExecutablePath: "/foo/path",
			Role:                  "role1",
			RoleChain:             []string{"role-123"},
		},
		ProviderUrl: "https://my-idp.com/?app_id=testdd",
	}
	if err := cmd.ConfigFromFlags(conf, &cmd.RootCmdFlags{}, &cmd.SamlCmdFlags{Role: "role-overridden-from-flags"}, "me"); err != nil {
		t.Fatal(err)
	}
	want := &credentialexchange.CredentialConfig{
		ProviderUrl: "https://my-idp.com/?app_id=testdd",
		BaseConfig: credentialexchange.BaseConfig{
			BrowserExecutablePath: "/foo/path",
			Role:                  "role-overridden-from-flags",
			RoleChain:             []string{"role-123"},
			Username:              "me",
		},
	}
	if diff := deep.Equal(conf, want); len(diff) > 0 {
		t.Errorf("diff: %v", diff)
	}
}
