package credentialexchange_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"testing"
	"time"

	"github.com/DevLabFoundry/aws-cli-auth/internal/credentialexchange"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/aws/smithy-go"
)

type mockAuthApi struct {
	assumeRoleWSaml func(ctx context.Context, params *sts.AssumeRoleWithSAMLInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleWithSAMLOutput, error)
	getCallId       func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
	assume          func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error)
}

func (m *mockAuthApi) AssumeRoleWithSAML(ctx context.Context, params *sts.AssumeRoleWithSAMLInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleWithSAMLOutput, error) {
	return m.assumeRoleWSaml(ctx, params, optFns...)
}

func (m *mockAuthApi) GetCallerIdentity(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	return m.getCallId(ctx, params, optFns...)
}

func (m *mockAuthApi) AssumeRole(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
	return m.assume(ctx, params, optFns...)
}

var mockSuccessAwsCreds = &types.Credentials{
	AccessKeyId:     aws.String("123"),
	SecretAccessKey: aws.String("456"),
	SessionToken:    aws.String("abcd"),
	Expiration:      aws.Time(time.Now().Local().Add(time.Duration(15) * time.Minute)),
}

func Test_AssumeWithSaml_(t *testing.T) {
	ttests := map[string]struct {
		srv       func(t *testing.T) credentialexchange.AuthSamlApi
		expectErr bool
		errTyp    error
	}{
		"succeeds with correct input": {
			srv: func(t *testing.T) credentialexchange.AuthSamlApi {
				m := &mockAuthApi{}
				m.assumeRoleWSaml = func(ctx context.Context, params *sts.AssumeRoleWithSAMLInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleWithSAMLOutput, error) {
					if *params.RoleArn != "somerole" {
						t.Errorf("expected role: %s got: %s", "somerole", *params.RoleArn)
					}
					return &sts.AssumeRoleWithSAMLOutput{
						AssumedRoleUser: &types.AssumedRoleUser{Arn: aws.String("somearn")},
						Credentials:     mockSuccessAwsCreds,
					}, nil
				}
				return m
			},
			expectErr: false,
			errTyp:    nil,
		},
		"fails on input": {
			srv: func(t *testing.T) credentialexchange.AuthSamlApi {
				m := &mockAuthApi{}
				m.assumeRoleWSaml = func(ctx context.Context, params *sts.AssumeRoleWithSAMLInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleWithSAMLOutput, error) {
					if *params.RoleArn != "somerole" {
						t.Errorf("expected role: %s got: %s", "somerole", *params.RoleArn)
					}
					return nil, fmt.Errorf("some error")
				}
				return m
			},
			expectErr: true,
			errTyp:    credentialexchange.ErrUnableAssume,
		},
	}
	for name, tt := range ttests {
		t.Run(name, func(t *testing.T) {
			got, err := credentialexchange.LoginStsSaml(context.TODO(), "samlAssertion...372dgh8ybjsdfviwehfiu9rwfe",
				credentialexchange.AWSRole{
					RoleARN:      "somerole",
					PrincipalARN: "someprincipal",
					Duration:     900,
				},
				tt.srv(t),
			)

			if tt.expectErr {
				if err == nil {
					t.Errorf("got <nil>, wanted %s", tt.errTyp)
				}
				if !errors.Is(err, tt.errTyp) {
					t.Errorf("got %s, wanted %s", err, tt.errTyp)
				}
				return
			}

			if err != nil {
				t.Fatalf("got %s, wanted <nil>", err)
			}
			if err != nil {
				t.Errorf("expected error: nil\n\ngot: %s", err)
			}
			if got.AWSSessionToken != "abcd" {
				t.Errorf("incorrect session token\nwanted: %s\ngot: %s", "abcd", got.AWSSessionToken)
			}
		})
	}
}

type smithyErrTyp struct {
	err      func() string
	errCode  func() string
	errMsg   func() string
	errFault func() smithy.ErrorFault
}

func (e *smithyErrTyp) Error() string {
	return e.err()
}
func (e *smithyErrTyp) ErrorCode() string {
	return e.errCode()
}

// ErrorMessage returns the error message for the API exception.
func (e *smithyErrTyp) ErrorMessage() string {
	return e.errMsg()
}

// ErrorFault returns the fault for the API exception.
func (e *smithyErrTyp) ErrorFault() smithy.ErrorFault {
	return e.errFault()
}

func Test_IsValid_with(t *testing.T) {
	ttests := map[string]struct {
		srv          func(t *testing.T) credentialexchange.AuthSamlApi
		currCred     *credentialexchange.AWSCredentials
		reloadBefore int
		expectValid  bool
		expectErr    bool
		errTyp       error
	}{
		"non expired credential with enough time before reload required": {
			func(t *testing.T) credentialexchange.AuthSamlApi {
				m := &mockAuthApi{}
				m.getCallId = func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
					return &sts.GetCallerIdentityOutput{
						Account: aws.String("account"),
						Arn:     aws.String("arn"),
					}, nil
				}
				return m
			},
			&credentialexchange.AWSCredentials{
				AWSAccessKey:    "stringjsonAccessKey",
				AWSSecretKey:    "stringjsonSecretAccessKey",
				AWSSessionToken: "stringjsonSessionToken",
				Expires:         time.Now().Local().Add(time.Duration(15) * time.Minute),
			},
			120,
			true,
			false,
			nil,
		},
		"credentials valid but need to reload before time fails": {
			func(t *testing.T) credentialexchange.AuthSamlApi {
				m := &mockAuthApi{}
				m.getCallId = func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
					return &sts.GetCallerIdentityOutput{
						Account: aws.String("account"),
						Arn:     aws.String("arn"),
					}, nil
				}
				return m
			},
			&credentialexchange.AWSCredentials{
				AWSAccessKey:    "stringjsonAccessKey",
				AWSSecretKey:    "stringjsonSecretAccessKey",
				AWSSessionToken: "stringjsonSessionToken",
				Expires:         time.Now().Local().Add(time.Duration(-15) * time.Minute),
			},
			120,
			false,
			false,
			nil,
		},
		"expired credential": {
			func(t *testing.T) credentialexchange.AuthSamlApi {
				m := &mockAuthApi{}
				m.getCallId = func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
					return nil, &smithyErrTyp{
						err:     func() string { return "some errr" },
						errCode: func() string { return "ExpiredToken" },
					}
				}
				return m
			},
			&credentialexchange.AWSCredentials{
				AWSAccessKey:    "stringjsonAccessKey",
				AWSSecretKey:    "stringjsonSecretAccessKey",
				AWSSessionToken: "stringjsonSessionToken",
				Expires:         time.Now().Local().Add(time.Duration(-15) * time.Minute),
			},
			120,
			false,
			false,
			nil,
		},
		"another error when chekcing credential": {
			func(t *testing.T) credentialexchange.AuthSamlApi {
				m := &mockAuthApi{}
				m.getCallId = func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
					return nil, &smithyErrTyp{
						err:     func() string { return "some errr" },
						errCode: func() string { return "SomeOTherErr" },
					}
				}
				return m
			},
			&credentialexchange.AWSCredentials{
				AWSAccessKey:    "stringjsonAccessKey",
				AWSSecretKey:    "stringjsonSecretAccessKey",
				AWSSessionToken: "stringjsonSessionToken",
				Expires:         time.Now().Local().Add(time.Duration(-15) * time.Minute),
			},
			120,
			false,
			true,
			credentialexchange.ErrUnableAssume,
		},
		"no existing credential": {
			func(t *testing.T) credentialexchange.AuthSamlApi {
				m := &mockAuthApi{}
				return m
			},
			nil,
			120,
			false,
			false,
			nil,
		},
	}
	for name, tt := range ttests {
		t.Run(name, func(t *testing.T) {
			valid, err := credentialexchange.IsValid(context.TODO(), tt.currCred, tt.reloadBefore, tt.srv(t))

			if tt.expectErr {
				if err == nil {
					t.Errorf("got <nil>, wanted %s", tt.errTyp)
					return
				}
				if !errors.Is(err, tt.errTyp) {
					t.Errorf("got %s, wanted %s", err, tt.errTyp)
					return
				}
			}

			if err != nil && !tt.expectErr {
				t.Errorf("got %s, wanted <nil>", err)
			}

			if valid != tt.expectValid {
				t.Errorf("expected %v, got %v", tt.expectValid, valid)
			}
		})
	}
}

type authWebTokenApi struct {
	assumewithwebId func(ctx context.Context, params *sts.AssumeRoleWithWebIdentityInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error)
}

func (a *authWebTokenApi) AssumeRoleWithWebIdentity(ctx context.Context, params *sts.AssumeRoleWithWebIdentityInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error) {
	return a.assumewithwebId(ctx, params, optFns...)
}

func Test_LoginAwsWebToken_with(t *testing.T) {
	ttests := map[string]struct {
		srv       func(t *testing.T) *authWebTokenApi
		setup     func() func()
		currCred  *credentialexchange.AWSCredentials
		expectErr bool
		errTyp    error
	}{
		"succeeds with correct input": {
			srv: func(t *testing.T) *authWebTokenApi {
				a := &authWebTokenApi{}
				a.assumewithwebId = func(ctx context.Context, params *sts.AssumeRoleWithWebIdentityInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error) {
					return &sts.AssumeRoleWithWebIdentityOutput{
						AssumedRoleUser: &types.AssumedRoleUser{Arn: aws.String("assumedRoleUser")},
						Credentials:     mockSuccessAwsCreds,
					}, nil
				}
				return a
			},
			setup: func() func() {
				tmpDir, _ := os.MkdirTemp(os.TempDir(), "web-id")
				tokenFile := path.Join(tmpDir, ".ignore-token")
				_ = os.WriteFile(tokenFile, []byte(`sometoikonsebjsxd`), 0777)
				_ = os.Setenv(credentialexchange.WEB_ID_TOKEN_VAR, tokenFile)
				_ = os.Setenv("AWS_ROLE_ARN", "somerole")
				return func() {
					os.Clearenv()
					_ = os.RemoveAll(tmpDir)
				}
			},
			currCred:  mockSuccessCreds,
			expectErr: false,
			errTyp:    nil,
		},
		"fails on rest call to assume": {
			srv: func(t *testing.T) *authWebTokenApi {
				a := &authWebTokenApi{}
				a.assumewithwebId = func(ctx context.Context, params *sts.AssumeRoleWithWebIdentityInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error) {
					return nil, fmt.Errorf("some err")
				}
				return a
			},
			setup: func() func() {
				tmpDir, _ := os.MkdirTemp(os.TempDir(), "web-id")
				tokenFile := path.Join(tmpDir, ".ignore-token")
				_ = os.WriteFile(tokenFile, []byte(`sometoikonsebjsxd`), 0777)
				_ = os.Setenv(credentialexchange.WEB_ID_TOKEN_VAR, tokenFile)
				_ = os.Setenv("AWS_ROLE_ARN", "somerole")
				return func() {
					os.Clearenv()
					_ = os.RemoveAll(tmpDir)
				}
			},
			currCred:  mockSuccessCreds,
			expectErr: true,
			errTyp:    credentialexchange.ErrUnableAssume,
		},
		"fails on missing role env VARS": {
			srv: func(t *testing.T) *authWebTokenApi {
				a := &authWebTokenApi{}
				a.assumewithwebId = func(ctx context.Context, params *sts.AssumeRoleWithWebIdentityInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error) {
					return &sts.AssumeRoleWithWebIdentityOutput{
						AssumedRoleUser: &types.AssumedRoleUser{Arn: aws.String("assumedRoleUser")},
						Credentials:     mockSuccessAwsCreds,
					}, nil
				}
				return a
			},
			setup: func() func() {
				return func() {}
			},
			currCred:  mockSuccessCreds,
			expectErr: true,
			errTyp:    credentialexchange.ErrMissingEnvVar,
		},
		"fails on missing token file env VARS": {
			srv: func(t *testing.T) *authWebTokenApi {
				a := &authWebTokenApi{}
				a.assumewithwebId = func(ctx context.Context, params *sts.AssumeRoleWithWebIdentityInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error) {
					return &sts.AssumeRoleWithWebIdentityOutput{
						AssumedRoleUser: &types.AssumedRoleUser{Arn: aws.String("assumedRoleUser")},
						Credentials:     mockSuccessAwsCreds,
					}, nil
				}
				return a
			},
			setup: func() func() {
				// tmpDir, _ := os.MkdirTemp(os.TempDir(), "web-id")
				// tokenFile := path.Join(tmpDir, ".ignore-token")
				// os.WriteFile(tokenFile, []byte(`sometoikonsebjsxd`), 0777)
				// os.Setenv(credentialexchange.WEB_ID_TOKEN_VAR, tokenFile)
				_ = os.Setenv("AWS_ROLE_ARN", "somerole")
				return func() {
					os.Clearenv()
					// os.RemoveAll(tmpDir)
				}
			},
			currCred:  mockSuccessCreds,
			expectErr: true,
			errTyp:    credentialexchange.ErrMissingEnvVar,
		},
	}
	for name, tt := range ttests {
		t.Run(name, func(t *testing.T) {
			tearDown := tt.setup()
			defer tearDown()

			got, err := credentialexchange.LoginAwsWebToken(context.TODO(), "username", tt.srv(t))

			if tt.expectErr {
				if err == nil {
					t.Errorf("got <nil>, wanted %s", tt.errTyp)
				}
				if !errors.Is(err, tt.errTyp) {
					t.Errorf("got %s, wanted %s", err, tt.errTyp)
				}
				return
			}

			if err != nil && !tt.expectErr {
				t.Fatalf("got %s, wanted <nil>", err)
			}

			if got.AWSAccessKey != *mockSuccessAwsCreds.AccessKeyId {
				t.Fatalf("expected %v, got %v", mockSuccessAwsCreds, got)
			}
		})
	}
}

func Test_AssumeSpecifiedCreds_with(t *testing.T) {
	ttests := map[string]struct {
		srv       func(t *testing.T) *mockAuthApi
		currCred  *credentialexchange.AWSCredentials
		expectErr bool
		errTyp    error
	}{
		"successfully passed in creds from somewhere": {
			srv: func(t *testing.T) *mockAuthApi {
				m := &mockAuthApi{}
				m.assume = func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
					return &sts.AssumeRoleOutput{
						AssumedRoleUser: &types.AssumedRoleUser{Arn: aws.String("somearn")},
						Credentials:     mockSuccessAwsCreds,
					}, nil
				}
				return m
			},
		},
		"error on calling AssumeRole API": {
			srv: func(t *testing.T) *mockAuthApi {
				m := &mockAuthApi{}
				m.assume = func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
					return nil, fmt.Errorf("some error")
				}
				return m
			},
			expectErr: true,
			errTyp:    credentialexchange.ErrUnableAssume,
		},
	}
	for name, tt := range ttests {
		t.Run(name, func(t *testing.T) {
			got, err := credentialexchange.AssumeRoleInChain(context.TODO(), tt.currCred, tt.srv(t), "foo", []string{"barrole"}, credentialexchange.CredentialConfig{Duration: 14400})

			if tt.expectErr {
				if err == nil {
					t.Errorf("got <nil>, wanted %s", tt.errTyp)
				}
				if !errors.Is(err, tt.errTyp) {
					t.Errorf("got %s, wanted %s", err, tt.errTyp)
				}
				return
			}

			if err != nil {
				t.Fatalf("got %s, wanted <nil>", err)
			}

			if got.AWSAccessKey != *mockSuccessAwsCreds.AccessKeyId {
				t.Fatalf("expected %v, got %v", mockSuccessAwsCreds, got)
			}
		})
	}
}

func Test_GetCredentialFromRoleCreds(t *testing.T) {
	ttests := map[string]struct {
		input     string
		expect    *credentialexchange.AWSCredentials
		expectErr bool
		errTyp    error
	}{
		"succeeds with escaped format": {
			"{\"roleCredentials\":{\"accessKeyId\":\"asdas\",\"secretAccessKey\":\"sa/08asc62pun9a\",\"sessionToken\":\"somtoken//////////YO4Dm0aJYq4K2rQ9V0B6yJMsKpkc5fo+iUT6nI99cZWmGFE\",\"expiration\":1698943755000}}",
			&credentialexchange.AWSCredentials{
				AWSAccessKey: "asdas",
			},
			false, nil,
		},
		"succeeds with unescaped format": {
			`{"roleCredentials":{"accessKeyId":"asdas","secretAccessKey":"sa/08asc62pun9a","sessionToken":"somtoken//////////YO4Dm0aJYq4K2rQ9V0B6yJMsKpkc5fo+iUT6nI99cZWmGFE","expiration":1698943755000}}`,
			&credentialexchange.AWSCredentials{
				AWSAccessKey: "asdas",
			},
			false, nil,
		},
	}
	for name, tt := range ttests {
		t.Run(name, func(t *testing.T) {
			a := &credentialexchange.AWSCredentials{}
			got, err := a.FromRoleCredString(tt.input)
			if tt.expectErr {
				if err == nil {
					t.Errorf("got <nil>, wanted %s", tt.errTyp)
				}
				if !errors.Is(err, tt.errTyp) {
					t.Errorf("got %s, wanted %s", err, tt.errTyp)
				}
				return
			}

			if err != nil {
				t.Fatalf("got %s, wanted <nil>", err)
			}

			if err != nil {
				t.Fatal(err)
			}
			if got.AWSAccessKey != tt.expect.AWSAccessKey {
				t.Fatal("not matched")
			}
		})
	}
}
