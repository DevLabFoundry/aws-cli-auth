package cmd_test

import (
	"bytes"
	"io"
	"testing"

	"github.com/DevLabFoundry/aws-cli-auth/cmd"
)

func Test_helpers_for_command(t *testing.T) {
	ttests := map[string]struct{}{
		"clear-cache": {},
		"saml":        {},
		"specific":    {},
	}
	for name := range ttests {
		t.Run(name, func(t *testing.T) {
			cmdArgs := []string{name, "--help"}
			b := new(bytes.Buffer)
			o := new(bytes.Buffer)
			cmd := cmd.RootCmd
			cmd.SetArgs(cmdArgs)
			cmd.SetErr(b)
			cmd.SetOut(o)
			cmd.Execute()
			err, _ := io.ReadAll(b)
			if len(err) > 0 {
				t.Fatal("got err, wanted nil")
			}
			out, _ := io.ReadAll(o)
			if len(out) <= 0 {
				t.Fatalf("got empty, wanted a help message")
			}
		})
	}
}

func Test_Saml(t *testing.T) {
	t.Skip()
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
		b := new(bytes.Buffer)
		o := new(bytes.Buffer)
		cmd := cmd.RootCmd
		cmd.SetArgs(cmdArgs)
		cmd.SetErr(b)
		cmd.SetOut(o)
		if err := cmd.Execute(); err == nil {
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
