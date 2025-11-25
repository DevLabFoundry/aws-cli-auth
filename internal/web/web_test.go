package web_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/DevLabFoundry/aws-cli-auth/internal/credentialexchange"
	"github.com/DevLabFoundry/aws-cli-auth/internal/web"
)

func mockIdpHandler(t *testing.T) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/saml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Server", "Server")
		w.Header().Set("X-Amzn-Requestid", "9363fdebc232c348b71c8ba5b59f9a34")
		// w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<!DOCTYPE html>
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
		_, _ = w.Write([]byte(`<!DOCTYPE html>
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
		_, _ = w.Write([]byte(`<!DOCTYPE html>
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
		_, _ = w.Write([]byte(`<!DOCTYPE html>
		<html>
		  <body>
			<div id="message">SomeApp</div>
		  </body>
		</html>`))
	})
	return mux
}

func Test_WebUI_with_succesful_saml(t *testing.T) {

	ts := httptest.NewServer(mockIdpHandler(t))
	defer ts.Close()
	conf := credentialexchange.CredentialConfig{BaseConfig: credentialexchange.BaseConfig{}}
	conf.AcsUrl = fmt.Sprintf("%s/saml", ts.URL)
	conf.ProviderUrl = fmt.Sprintf("%s/idp-onload", ts.URL)

	tempDir, _ := os.MkdirTemp(os.TempDir(), "web-saml-tester")

	defer func() {
		os.RemoveAll(tempDir)
	}()

	webUi, err := web.New(context.TODO(), web.NewWebConf(tempDir).WithHeadless().WithTimeout(10).WithNoSandbox())
	if err != nil {
		t.Fatal(err)
	}
	saml, err := webUi.GetSamlLogin(conf)
	if err != nil {
		t.Errorf("expected err to be <nil> got: %s", err)
	}
	if saml != "dsicisud99u2ubf92e9euhre" {
		t.Errorf("incorrect saml returned\n expected \"dsicisud99u2ubf92e9euhre\", got: %s", saml)
	}
}

func Test_WebUI_timeout_and_return_error(t *testing.T) {

	ts := httptest.NewServer(mockIdpHandler(t))
	defer ts.Close()
	conf := credentialexchange.CredentialConfig{BaseConfig: credentialexchange.BaseConfig{}}
	conf.AcsUrl = fmt.Sprintf("%s/saml", ts.URL)
	conf.ProviderUrl = fmt.Sprintf("%s/idp-onload", ts.URL)

	tempDir, _ := os.MkdirTemp(os.TempDir(), "web-saml-tester")

	defer func() {
		os.RemoveAll(tempDir)
	}()

	webUi, err := web.New(context.TODO(), web.NewWebConf(tempDir).WithHeadless().WithTimeout(0).WithNoSandbox())
	if err != nil {
		t.Fatal(err)
	}
	_, err = webUi.GetSamlLogin(conf)

	if !errors.Is(err, web.ErrTimedOut) {
		t.Errorf("incorrect error returned\n expected: %s, got: %s", web.ErrTimedOut, err)
	}
}

func Test_ClearCache(t *testing.T) {
	t.Skip("no longer relevant")
}

func mockSsoHandler(t *testing.T) http.Handler {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Server", "Server")
		w.Header().Set("X-Amzn-Requestid", "9363fdebc232c348b71c8ba5b59f9a34")
		_, _ = w.Write([]byte(``))
	})
	mux.HandleFunc("/fed-endpoint", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`{"roleCredentials":{"accessKeyId":"asdas","secretAccessKey":"sa/08asc62pun9a","sessionToken":"somtoken//////////YO4Dm0aJYq4K2rQ9V0B6yJMsKpkc5fo+iUT6nI99cZWmGFE","expiration":1698943755000}}`))
	})
	mux.HandleFunc("/idp-onload", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!DOCTYPE html>
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

func Test_WebUI_with_succesful_ssoLogin(t *testing.T) {

	ts := httptest.NewServer(mockSsoHandler(t))
	defer ts.Close()
	conf := credentialexchange.CredentialConfig{
		IsSso:              true,
		SsoUserEndpoint:    fmt.Sprintf("%s/user", ts.URL),
		SsoCredFedEndpoint: fmt.Sprintf("%s/fed-endpoint", ts.URL),
		ProviderUrl:        fmt.Sprintf("%s/idp-onload", ts.URL),
		AcsUrl:             fmt.Sprintf("%s/saml", ts.URL),
		BaseConfig:         credentialexchange.BaseConfig{},
	}

	tempDir, _ := os.MkdirTemp(os.TempDir(), "web-sso-tester")

	defer func() {
		os.RemoveAll(tempDir)
	}()

	webUi, err := web.New(context.TODO(), web.NewWebConf(tempDir).WithHeadless().WithTimeout(10).WithNoSandbox())
	if err != nil {
		t.Fatal(err)
	}
	creds, err := webUi.GetSSOCredentials(conf)
	if err != nil {
		t.Errorf("expected err to be <nil> got: %s", err)
	}
	if creds != `{"roleCredentials":{"accessKeyId":"asdas","secretAccessKey":"sa/08asc62pun9a","sessionToken":"somtoken//////////YO4Dm0aJYq4K2rQ9V0B6yJMsKpkc5fo+iUT6nI99cZWmGFE","expiration":1698943755000}}` {
		t.Errorf("incorrect saml returned\n expected \"dsicisud99u2ubf92e9euhre\", got: %s", creds)
	}
}

func Test_WebUI_with_timeout_ssoLogin(t *testing.T) {

	ts := httptest.NewServer(mockSsoHandler(t))
	defer ts.Close()
	conf := credentialexchange.CredentialConfig{
		IsSso:              true,
		SsoUserEndpoint:    fmt.Sprintf("%s/user", ts.URL),
		SsoCredFedEndpoint: fmt.Sprintf("%s/fed-endpoint", ts.URL),
		ProviderUrl:        fmt.Sprintf("%s/idp-onload", ts.URL),
		AcsUrl:             fmt.Sprintf("%s/saml", ts.URL),
		BaseConfig:         credentialexchange.BaseConfig{},
	}

	tempDir, _ := os.MkdirTemp(os.TempDir(), "web-sso-tester")

	defer func() {
		os.RemoveAll(tempDir)
	}()

	webUi, err := web.New(context.TODO(), web.NewWebConf(tempDir).WithHeadless().WithTimeout(0).WithNoSandbox())
	if err != nil {
		t.Fatal(err)
	}
	_, err = webUi.GetSSOCredentials(conf)

	if !errors.Is(err, web.ErrTimedOut) {
		t.Errorf("incorrect error returned\n expected: %s, got: %s", web.ErrTimedOut, err)
	}
}

func Test_Web_BuildLauncher(t *testing.T) {
	ttests := map[string]struct {
		customExe string
		wantBin   string
	}{
		"with custom executable": {
			customExe: "/fooo",
			wantBin:   "/fooo",
		},
		"without custom": {
			customExe: "/path/to/another",
			wantBin:   "/path/to/another",
		},
	}
	for name, tt := range ttests {
		t.Run(name, func(t *testing.T) {
			got := web.BuildLauncher(context.TODO(), &web.WebConfig{CustomChromeExecutable: tt.customExe})

			bin := got.Get("rod-bin")
			if len(bin) < 1 && tt.wantBin != "" {
				t.Fatal("got no custom binary paths")
			}
			if bin != tt.wantBin {
				t.Fatalf("got %v, want %v", bin, tt.wantBin)
			}
		})
	}

	t.Run("default browser is returned when no custom binary specified", func(t *testing.T) {
		// for people running this locally without a default chrome/chromium installed this will potentially fail
		//
		// run the tests in the `eirctl run unit:test:run`
		//
		got := web.BuildLauncher(context.TODO(), &web.WebConfig{CustomChromeExecutable: ""})
		bin := got.Get("rod-bin")
		if len(bin) < 1 {
			t.Fatal("got no binary paths")
		}
	})
}
