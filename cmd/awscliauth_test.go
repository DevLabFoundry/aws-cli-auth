package cmd_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/DevLabFoundry/aws-cli-auth/cmd"
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
