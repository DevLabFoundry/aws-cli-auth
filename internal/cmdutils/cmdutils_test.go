package cmdutils_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/DevLabFoundry/aws-cli-auth/internal/cmdutils"
	"github.com/DevLabFoundry/aws-cli-auth/internal/credentialexchange"
	"github.com/DevLabFoundry/aws-cli-auth/internal/web"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
	"gopkg.in/ini.v1"
)

func AwsMockHandler(t *testing.T, mux *http.ServeMux) http.Handler {

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		for k, v := range r.URL.Query() {
			fmt.Println(k, " => ", v)
		}
		fmt.Println(r.URL.Query().Get("Action"))
		// if r.Form.Get("Action") == "AssumeRoleWithSAML" {
		w.Header().Set("Content-Type", "application/xml; charset=utf-8")
		w.Write([]byte(`<AssumeRoleWithSAMLResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
    <AssumeRoleWithSAMLResult>
        <Issuer> https://integ.example.com/idp/shibboleth</Issuer>
        <AssumedRoleUser>
            <Arn>arn:aws:sts::1122223334:assumed-role/some-role</Arn>
            <AssumedRoleId>ARO456EXAMPLE789:some-role</AssumedRoleId>
        </AssumedRoleUser>
        <Credentials>
            <AccessKeyId>ASIAV3ZUEFP6EXAMPLE</AccessKeyId>
            <SecretAccessKey>8P+SQvWIuLnKhh8d++jpw0nNmQRBZvNEXAMPLEKEY</SecretAccessKey>
            <SessionToken> IQoJb3JpZ2luX2VjEOz////////////////////wEXAMPLEtMSJHMEUCIDoKK3JH9uG
                QE1z0sINr5M4jk+Na8KHDcCYRVjJCZEvOAiEA3OvJGtw1EcViOleS2vhs8VdCKFJQWP
                QrmGdeehM4IC1NtBmUpp2wUE8phUZampKsburEDy0KPkyQDYwT7WZ0wq5VSXDvp75YU
                9HFvlRd8Tx6q6fE8YQcHNVXAkiY9q6d+xo0rKwT38xVqr7ZD0u0iPPkUL64lIZbqBAz
                +scqKmlzm8FDrypNC9Yjc8fPOLn9FX9KSYvKTr4rvx3iSIlTJabIQwj2ICCR/oLxBA== </SessionToken>
            <Expiration>2030-11-01T20:26:47Z</Expiration>
        </Credentials>
        <Audience>https://signin.aws.amazon.com/saml</Audience>
        <SubjectType>transient</SubjectType>
        <PackedPolicySize>6</PackedPolicySize>
        <NameQualifier>SbdGOnUkh1i4+EXAMPLExL/jEvs=</NameQualifier>
        <SourceIdentity>SourceIdentityValue</SourceIdentity>
        <Subject>SamlExample</Subject>
    </AssumeRoleWithSAMLResult>
    <ResponseMetadata>
        <RequestId>c6104cbe-af31-11e0-8154-cbc7ccf896c7</RequestId>
    </ResponseMetadata>
</AssumeRoleWithSAMLResponse>`))
	})
	return mux
}

func IdpHandler(t *testing.T, addAwsMock bool) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/saml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Server", "Server")
		w.Header().Set("X-Amzn-Requestid", "9363fdebc232c348b71c8ba5b59f9a34")
		// w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<!DOCTYPE html>
		<html>
		<head></head>
		<body>
		SAMLResponse=dsicisud99u2ubf92e9euhre&RelayState=
		</body>
	  </html>
		`))
	})
	mux.HandleFunc("/idp-redirect", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(`<!DOCTYPE html>
		<html>
		<head>
		<script type="text/javascript">
			function callSaml() {
				var xhr = new XMLHttpRequest();
				xhr.open("POST", "/saml");
				xhr.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
				xhr.setRequestHeader("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8")
				xhr.send('SAMLResponse=dsicisud99u2ubf92e9euhre');
			  }
			  document.addEventListener('DOMContentLoaded', function() {
				// setInterval(callSaml, 100)
				callSaml()
				let message = document.getElementById("message");
				message.innerHTML = JSON.stringify({})
				// setTimeout(() => window.location.href = "/saml", 100)
		  }, false);
		</script>
		</head>
		  <body>
			<div id="message"></div>
		  </body>
		</html>`))
	})
	mux.HandleFunc("/idp-onload", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(`<!DOCTYPE html>
		<html>
		  <body">
			<div id="message"></div>
		  </body>
		  <script type="text/javascript">
			document.addEventListener('DOMContentLoaded', function() {
				setTimeout(() => {window.location.href = "/idp-redirect"}, 100)
			}, false);
		  </script>
		</html>`))
	})
	mux.HandleFunc("/some-app", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(`<!DOCTYPE html>
		<html>
		  <body>
			<div id="message">SomeApp</div>
		  </body>
		</html>`))
	})
	if addAwsMock {
		return AwsMockHandler(t, mux)
	}
	return mux
}

func testConfig() credentialexchange.CredentialConfig {
	return credentialexchange.CredentialConfig{
		BaseConfig: credentialexchange.BaseConfig{
			Role:             "arn:aws:iam::1122223334:role/some-role",
			StoreInProfile:   false,
			ReloadBeforeTime: 850,
		},
		PrincipalArn: "arn:aws:iam::1122223334:saml-provider/some-provider",
		Duration:     900,
	}
}

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

type mockSecretApi struct {
	mCred     func() (*credentialexchange.AWSCredentials, error)
	mclear    func() error
	mClearAll func(cfg *ini.File) error
	mSave     func(cred *credentialexchange.AWSCredentials) error
}

func (s *mockSecretApi) AWSCredential() (*credentialexchange.AWSCredentials, error) {
	return s.mCred()
}

func (s *mockSecretApi) Clear() error {
	return s.mclear()
}

func (s *mockSecretApi) ClearAll(cfg *ini.File) error {
	return s.mClearAll(cfg)
}

func (s *mockSecretApi) SaveAWSCredential(cred *credentialexchange.AWSCredentials) error {
	return s.mSave(cred)
}

func Test_GetSamlCreds_With(t *testing.T) {
	ttests := map[string]struct {
		config      func(t *testing.T) credentialexchange.CredentialConfig
		handler     func(t *testing.T, awsMock bool) http.Handler
		authApi     func(t *testing.T) credentialexchange.AuthSamlApi
		secretStore func(t *testing.T) cmdutils.SecretStorageImpl
		expectErr   bool
		errTyp      error
	}{
		"correct config and extracted creds but not valid anymore": {
			config: func(t *testing.T) credentialexchange.CredentialConfig {
				return testConfig()
			},
			handler: IdpHandler,
			authApi: func(t *testing.T) credentialexchange.AuthSamlApi {
				m := &mockAuthApi{}
				m.assumeRoleWSaml = func(ctx context.Context, params *sts.AssumeRoleWithSAMLInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleWithSAMLOutput, error) {
					return &sts.AssumeRoleWithSAMLOutput{
						AssumedRoleUser: &types.AssumedRoleUser{
							AssumedRoleId: aws.String("some-role"),
							Arn:           aws.String("arn"),
						},
						Audience: new(string),
						Credentials: &types.Credentials{
							AccessKeyId:     aws.String("123213"),
							SecretAccessKey: aws.String("32798hewf"),
							SessionToken:    aws.String("49hefusdSOM_LONG_TOKEN_HERE"),
							Expiration:      aws.Time(time.Now().Local().Add(time.Minute * time.Duration(5))),
						},
						Issuer:           new(string),
						NameQualifier:    new(string),
						PackedPolicySize: new(int32),
						SourceIdentity:   new(string),
						Subject:          new(string),
						SubjectType:      new(string),
					}, nil
				}

				m.getCallId = func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
					// t.Error()
					return &sts.GetCallerIdentityOutput{
						Account: aws.String("1122223334"),
						Arn:     aws.String("arn:aws:iam::1122223334:role/some-role"),
						UserId:  aws.String("some-user-id"),
					}, nil
				}
				m.assume = func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
					return &sts.AssumeRoleOutput{
						AssumedRoleUser: &types.AssumedRoleUser{
							AssumedRoleId: aws.String("some-role"),
							Arn:           aws.String("arn"),
						},
						Credentials: &types.Credentials{
							AccessKeyId:     aws.String("123213"),
							SecretAccessKey: aws.String("32798hewf"),
							SessionToken:    aws.String("49hefusdSOM_LONG_TOKEN_HERE"),
							Expiration:      aws.Time(time.Now().Local().Add(time.Minute * time.Duration(5))),
						},
					}, nil
				}
				return m
			},
			secretStore: func(t *testing.T) cmdutils.SecretStorageImpl {
				ss := &mockSecretApi{}
				ss.mCred = func() (*credentialexchange.AWSCredentials, error) {
					return &credentialexchange.AWSCredentials{
						Version:         1,
						AWSAccessKey:    "3212321",
						AWSSecretKey:    "23fsd2332",
						AWSSessionToken: "LONG_TOKEN",
						Expires:         time.Now().Local().Add(time.Minute * time.Duration(-1)),
					}, nil
				}
				ss.mSave = func(cred *credentialexchange.AWSCredentials) error {
					return nil
				}
				return ss
			},
			expectErr: false,
			errTyp:    nil,
		},
		"correct config and extracted creds an IsValid": {
			config: func(t *testing.T) credentialexchange.CredentialConfig {
				conf := testConfig()
				conf.BaseConfig.ReloadBeforeTime = 60
				return conf
			},
			handler: IdpHandler,
			authApi: func(t *testing.T) credentialexchange.AuthSamlApi {
				m := &mockAuthApi{}
				m.assumeRoleWSaml = func(ctx context.Context, params *sts.AssumeRoleWithSAMLInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleWithSAMLOutput, error) {
					return &sts.AssumeRoleWithSAMLOutput{
						AssumedRoleUser: &types.AssumedRoleUser{
							AssumedRoleId: aws.String("some-role"),
							Arn:           aws.String("arn"),
						},
						Audience: new(string),
						Credentials: &types.Credentials{
							AccessKeyId:     aws.String("123213"),
							SecretAccessKey: aws.String("32798hewf"),
							SessionToken:    aws.String("49hefusdSOM_LONG_TOKEN_HERE"),
							Expiration:      aws.Time(time.Now().Local().Add(time.Minute * time.Duration(5))),
						},
						Issuer:           new(string),
						NameQualifier:    new(string),
						PackedPolicySize: new(int32),
						SourceIdentity:   new(string),
						Subject:          new(string),
						SubjectType:      new(string),
					}, nil
				}

				m.getCallId = func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
					// t.Error()
					return &sts.GetCallerIdentityOutput{
						Account: aws.String("1122223334"),
						Arn:     aws.String("arn:aws:iam::1122223334:role/some-role"),
						UserId:  aws.String("some-user-id"),
					}, nil
				}

				return m
			},
			secretStore: func(t *testing.T) cmdutils.SecretStorageImpl {
				ss := &mockSecretApi{}
				ss.mCred = func() (*credentialexchange.AWSCredentials, error) {
					return &credentialexchange.AWSCredentials{
						Version:         1,
						AWSAccessKey:    "3212321",
						AWSSecretKey:    "23fsd2332",
						AWSSessionToken: "LONG_TOKEN",
						Expires:         time.Now().Local().Add(time.Minute * time.Duration(10)),
					}, nil
				}
				ss.mSave = func(cred *credentialexchange.AWSCredentials) error {
					return nil
				}
				return ss
			},
			expectErr: false,
			errTyp:    nil,
		},
		"mising config section name and --store-in-profile set": {
			config: func(t *testing.T) credentialexchange.CredentialConfig {
				tc := testConfig()
				tc.BaseConfig.CfgSectionName = ""
				tc.BaseConfig.StoreInProfile = true
				return tc
			},
			handler: IdpHandler,
			authApi: func(t *testing.T) credentialexchange.AuthSamlApi {
				return &mockAuthApi{}
			},
			secretStore: func(t *testing.T) cmdutils.SecretStorageImpl {
				ss := &mockSecretApi{}
				ss.mCred = func() (*credentialexchange.AWSCredentials, error) {
					return &credentialexchange.AWSCredentials{
						AWSAccessKey:    "123",
						AWSSecretKey:    "12312s",
						AWSSessionToken: "session-token",
						PrincipalARN:    "some-arn"}, nil
				}
				return ss
			},
			expectErr: true,
			errTyp:    cmdutils.ErrMissingArg,
		},
		"failure on unable to retrieve existing credential": {
			config: func(t *testing.T) credentialexchange.CredentialConfig {
				tc := testConfig()
				tc.BaseConfig.CfgSectionName = ""
				tc.BaseConfig.StoreInProfile = false
				return tc
			},
			handler: IdpHandler,
			authApi: func(t *testing.T) credentialexchange.AuthSamlApi {
				return &mockAuthApi{}
			},
			secretStore: func(t *testing.T) cmdutils.SecretStorageImpl {
				ss := &mockSecretApi{}
				ss.mCred = func() (*credentialexchange.AWSCredentials, error) {
					return nil, fmt.Errorf("%w", credentialexchange.ErrUnableToLoadAWSCred)
				}
				return ss
			},
			expectErr: true,
			errTyp:    credentialexchange.ErrUnableToLoadAWSCred,
		},
		"fails on isValid": {
			config: func(t *testing.T) credentialexchange.CredentialConfig {
				tc := testConfig()
				tc.BaseConfig.CfgSectionName = ""
				tc.BaseConfig.StoreInProfile = false
				return tc
			},
			handler: IdpHandler,
			authApi: func(t *testing.T) credentialexchange.AuthSamlApi {
				m := &mockAuthApi{}
				m.getCallId = func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
					return nil, fmt.Errorf("get caller error")
				}

				return m
			},
			secretStore: func(t *testing.T) cmdutils.SecretStorageImpl {
				ss := &mockSecretApi{}
				ss.mCred = func() (*credentialexchange.AWSCredentials, error) {
					return &credentialexchange.AWSCredentials{
						Version:         1,
						AWSAccessKey:    "3212321",
						AWSSecretKey:    "23fsd2332",
						AWSSessionToken: "LONG_TOKEN",
						Expires:         time.Now().Local().Add(time.Minute * time.Duration(-1)),
					}, nil
				}
				return ss
			},
			expectErr: true,
			errTyp:    cmdutils.ErrUnableToValidate,
		},
	}
	for name, tt := range ttests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ts := httptest.NewServer(tt.handler(t, true))
			defer ts.Close()
			conf := tt.config(t)
			conf.AcsUrl = fmt.Sprintf("%s/saml", ts.URL)
			conf.ProviderUrl = fmt.Sprintf("%s/idp-onload", ts.URL)

			tempDir, _ := os.MkdirTemp(os.TempDir(), "saml-tester")

			defer func() {
				os.RemoveAll(tempDir)
			}()

			ss := tt.secretStore(t)

			err := cmdutils.GetCredsWebUI(
				context.TODO(), tt.authApi(t), ss, conf,
				web.NewWebConf(tempDir).WithHeadless().WithTimeout(10).WithNoSandbox())

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
		})
	}
}

func mockSsoHandler(t *testing.T) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Server", "Server")
		w.Header().Set("X-Amzn-Requestid", "9363fdebc232c348b71c8ba5b59f9a34")
		w.Write([]byte(``))
	})
	mux.HandleFunc("/fed-endpoint", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(`{"roleCredentials":{"accessKeyId":"asdas","secretAccessKey":"sa/08asc62pun9a","sessionToken":"somtoken//////////YO4Dm0aJYq4K2rQ9V0B6yJMsKpkc5fo+iUT6nI99cZWmGFE","expiration":1698943755000}}`))
	})
	mux.HandleFunc("/idp-onload", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(`<!DOCTYPE html>
		<html>
		  <body">
			<div id="message"></div>
		  </body>
		  <script type="text/javascript">
			document.addEventListener('DOMContentLoaded', function() {
				setTimeout(() => {window.location.href = "/user"}, 100)
			}, false);
		  </script>
		</html>`))
	})
	return mux
}

func Test_Get_SSO_Creds_with(t *testing.T) {
	t.Parallel()
	ttests := map[string]struct {
		config      func(t *testing.T) credentialexchange.CredentialConfig
		handler     func(t *testing.T) http.Handler
		authApi     func(t *testing.T) credentialexchange.AuthSamlApi
		secretStore func(t *testing.T) cmdutils.SecretStorageImpl
		expectErr   bool
		errTyp      error
	}{
		"correct outcome": {
			config: func(t *testing.T) credentialexchange.CredentialConfig {
				return testConfig()
			},
			handler: mockSsoHandler,
			authApi: func(t *testing.T) credentialexchange.AuthSamlApi {
				m := &mockAuthApi{}
				m.assumeRoleWSaml = func(ctx context.Context, params *sts.AssumeRoleWithSAMLInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleWithSAMLOutput, error) {
					return &sts.AssumeRoleWithSAMLOutput{}, nil
				}

				m.getCallId = func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
					// t.Error()
					return &sts.GetCallerIdentityOutput{}, nil
				}
				m.assume = func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
					return &sts.AssumeRoleOutput{
						AssumedRoleUser: &types.AssumedRoleUser{
							AssumedRoleId: aws.String("some-role"),
							Arn:           aws.String("arn"),
						},
						Credentials: &types.Credentials{
							AccessKeyId:     aws.String("123213"),
							SecretAccessKey: aws.String("32798hewf"),
							SessionToken:    aws.String("49hefusdSOM_LONG_TOKEN_HERE"),
							Expiration:      aws.Time(time.Now().Local().Add(time.Minute * time.Duration(5))),
						},
					}, nil
				}
				return m
			},
			secretStore: func(t *testing.T) cmdutils.SecretStorageImpl {
				ss := &mockSecretApi{}
				ss.mCred = func() (*credentialexchange.AWSCredentials, error) {
					return &credentialexchange.AWSCredentials{
						Version:         1,
						AWSAccessKey:    "3212321",
						AWSSecretKey:    "23fsd2332",
						AWSSessionToken: "LONG_TOKEN",
						Expires:         time.Now().Local().Add(time.Minute * time.Duration(-1)),
					}, nil
				}
				ss.mSave = func(cred *credentialexchange.AWSCredentials) error {
					return nil
				}
				return ss
			},
			expectErr: false,
			errTyp:    nil,
		},
	}
	for name, tt := range ttests {
		t.Run(name, func(t *testing.T) {
			ts := httptest.NewServer(tt.handler(t))
			defer ts.Close()
			conf := tt.config(t)
			conf.IsSso = true
			conf.SsoUserEndpoint = fmt.Sprintf("%s/user", ts.URL)
			conf.SsoCredFedEndpoint = fmt.Sprintf("%s/fed-endpoint", ts.URL)
			conf.ProviderUrl = fmt.Sprintf("%s/idp-onload", ts.URL)
			conf.AcsUrl = fmt.Sprintf("%s/saml", ts.URL)
			conf.BaseConfig = credentialexchange.BaseConfig{}

			tempDir, _ := os.MkdirTemp(os.TempDir(), "saml-sso-tester")

			defer func() {
				os.RemoveAll(tempDir)
			}()

			ss := tt.secretStore(t)

			err := cmdutils.GetCredsWebUI(
				context.TODO(), tt.authApi(t), ss, conf,
				web.NewWebConf(tempDir).WithHeadless().WithTimeout(10).WithNoSandbox())

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
		})
	}
}
