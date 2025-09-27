package cmd_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/DevLabFoundry/aws-cli-auth/cmd"
	"github.com/DevLabFoundry/aws-cli-auth/internal/credentialexchange"
	"github.com/DevLabFoundry/aws-cli-auth/internal/web"
)

func cmdHelperExecutor(t *testing.T, args []string) (stdOut *bytes.Buffer, errOut *bytes.Buffer, err error) {
	t.Helper()
	errOut = new(bytes.Buffer)
	stdOut = new(bytes.Buffer)
	c := cmd.New()
	c.WithSubCommands(cmd.SubCommands()...)
	c.Cmd.SetArgs(args)
	c.Cmd.SetErr(errOut)
	c.Cmd.SetOut(stdOut)
	err = c.Execute(context.Background())
	return stdOut, errOut, err
}

func Test_helpers_for_command(t *testing.T) {

	ttests := map[string]struct{}{
		"clear-cache": {},
		"saml":        {},
		"specific":    {},
	}
	for name := range ttests {
		t.Run(name, func(t *testing.T) {
			cmdArgs := []string{name, "--help"}
			stdOut, errOut, err := cmdHelperExecutor(t, cmdArgs)
			if err != nil {
				t.Fatal(err)
			}
			errCheck, _ := io.ReadAll(errOut)
			if len(errCheck) > 0 {
				t.Fatal("got err, wanted nil")
			}
			outCheck, _ := io.ReadAll(stdOut)
			if len(outCheck) <= 0 {
				t.Fatalf("got empty, wanted a help message")
			}
		})
	}
}

func Test_Saml_timeout(t *testing.T) {
	t.Run("standard non sso should fail with incorrect saml URLs", func(t *testing.T) {
		cmdArgs := []string{"saml", "-p",
			"https://httpbin.org/anything/app123",
			"--principal",
			"arn:aws:iam::1234111111111:saml-provider/provider1",
			"--role",
			"arn:aws:iam::1234111111111:role/Role-ReadOnly",
			"--role-chain",
			"arn:aws:iam::1234111111111:role/Kubernetes-Cluster-Administrators",
			"--saml-timeout", "1",
			"-d",
			"14400",
			"--reload-before",
			"120"}
		_, _, err := cmdHelperExecutor(t, cmdArgs)
		if err == nil && !errors.Is(err, web.ErrTimedOut) {
			t.Error("got nil, wanted an error")
		}
		// err, _ := io.ReadAll(b)
		// fmt.Println(string(err))
		// if len(err) <= 0 {
		// 	t.Fatal("got nil, wanted an error")
		// }
		// out, _ := io.ReadAll(o)
		// fmt.Println(string(out))
		// if len(out) <= 0 {
		// 	t.Fatalf("got empty, wanted a help message")
		// }
	})
}

func Test_SpecificCommand(t *testing.T) {

	t.Run("Sepcific command should fail with wrong method", func(t *testing.T) {
		_, _, err := cmdHelperExecutor(t, []string{"specific", "--method=unknown", "--role",
			"arn:aws:iam::1234111111111:role/Role-ReadOnly"})
		if err == nil {
			t.Error("got nil, wanted an error")
		}
		if !errors.Is(err, cmd.ErrUnsupportedMethod) {
			t.Errorf("got %v, wanted %v", err, cmd.ErrUnsupportedMethod)
		}
	})

	t.Run("Sepcific command fails on missing env AWS_WEB_IDENTITY_TOKEN_FILE", func(t *testing.T) {
		os.Setenv("AWS_ROLE_ARN", "arn:aws:iam::1234111111111:role/Role-ReadOnly")
		defer os.Unsetenv("AWS_ROLE_ARN")
		_, _, err := cmdHelperExecutor(t, []string{"specific", "--method=WEB_ID", "--role",
			"arn:aws:iam::1234111111111:role/Role-ReadOnly"})
		if err == nil {
			t.Error("got nil, wanted an error")
		}
		if !errors.Is(err, credentialexchange.ErrMissingEnvVar) {
			t.Errorf("got %v, wanted %v", err, cmd.ErrUnsupportedMethod)
		}
	})
}

func Test_ClearCommand(t *testing.T) {

	t.Run("should pass without --force", func(t *testing.T) {
		_, _, err := cmdHelperExecutor(t, []string{"clear-cache"})
		if err != nil {
			t.Error("got nil, wanted an error")
		}
	})
	t.Run("should warn user to manually delete data dir", func(t *testing.T) {
		stdout, _, err := cmdHelperExecutor(t, []string{"clear-cache", "--force"})
		if err != nil {
			t.Error("got nil, wanted an error")
		}
		if len(stdout.String()) < 1 {
			t.Fatal("got nil, wanted output")
		}
		if !strings.Contains(stdout.String(), "manually") {
			t.Errorf("incorrect messasge displayed, got %s, wanted to include manually", stdout.String())
		}
	})
}
