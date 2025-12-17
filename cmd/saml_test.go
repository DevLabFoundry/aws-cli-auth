package cmd_test

import (
	"errors"
	"testing"

	"github.com/DevLabFoundry/aws-cli-auth/cmd"
	"github.com/DevLabFoundry/aws-cli-auth/internal/credentialexchange"
	"github.com/go-test/deep"
)

func Test_ConfigMerge_succeeds(t *testing.T) {
	conf := &credentialexchange.CredentialConfig{
		BaseConfig: credentialexchange.BaseConfig{
			BrowserExecutablePath: "/foo/path",
			Role:                  "role1",
			RoleChain:             []string{"role-123"},
		},
		PrincipalArn: "aw:arn:....123",
		ProviderUrl:  "https://my-idp.com/?app_id=testdd",
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
		PrincipalArn: "aw:arn:....123",
	}
	if diff := deep.Equal(conf, want); len(diff) > 0 {
		t.Errorf("diff: %v", diff)
	}
}

func Test_ConfigMerge_fails_with_missing(t *testing.T) {
	t.Run("provider not provided", func(t *testing.T) {

		conf := &credentialexchange.CredentialConfig{
			BaseConfig: credentialexchange.BaseConfig{
				BrowserExecutablePath: "/foo/path",
				Role:                  "",
				RoleChain:             []string{"role-123"},
			},
			ProviderUrl: "",
		}
		err := cmd.ConfigFromFlags(conf, &cmd.RootCmdFlags{}, &cmd.SamlCmdFlags{Role: "role-overridden-from-flags"}, "me")
		if !errors.Is(err, cmd.ErrValidationFailed) {
			t.Error(err)
		}
	})
	t.Run("role not provided", func(t *testing.T) {

		conf := &credentialexchange.CredentialConfig{
			BaseConfig: credentialexchange.BaseConfig{
				BrowserExecutablePath: "/foo/path",
				Role:                  "",
				RoleChain:             []string{"role-123"},
			},
			ProviderUrl: "https://my-idp.com/?app_id=testdd",
		}
		err := cmd.ConfigFromFlags(conf, &cmd.RootCmdFlags{}, &cmd.SamlCmdFlags{}, "me")
		if !errors.Is(err, cmd.ErrValidationFailed) {
			t.Error(err)
		}
	})
	t.Run("is-sso set but sso-role not set", func(t *testing.T) {

		conf := &credentialexchange.CredentialConfig{
			BaseConfig: credentialexchange.BaseConfig{
				BrowserExecutablePath: "/foo/path",
				Role:                  "",
				RoleChain:             []string{"role-123"},
			},
			PrincipalArn: "some-arn",
			SsoRegion:    "foo",
			SsoRole:      "foo:bar",
			ProviderUrl:  "https://my-idp.com/?app_id=testdd",
		}
		err := cmd.ConfigFromFlags(conf, &cmd.RootCmdFlags{}, &cmd.SamlCmdFlags{Role: "wrong-role"}, "me")
		if !errors.Is(err, cmd.ErrValidationFailed) {
			t.Error(err)
		}
	})
	t.Run("role and sso-role both provided", func(t *testing.T) {

		conf := &credentialexchange.CredentialConfig{
			BaseConfig: credentialexchange.BaseConfig{
				BrowserExecutablePath: "/foo/path",
				Role:                  "",
				RoleChain:             []string{"role-123"},
			},
			PrincipalArn: "some-arn",
			SsoRegion:    "foo",
			SsoRole:      "foo:bar",
			ProviderUrl:  "https://my-idp.com/?app_id=testdd",
		}
		err := cmd.ConfigFromFlags(conf, &cmd.RootCmdFlags{}, &cmd.SamlCmdFlags{Role: "wrong-role"}, "me")
		if !errors.Is(err, cmd.ErrValidationFailed) {
			t.Error(err)
		}
	})
}
