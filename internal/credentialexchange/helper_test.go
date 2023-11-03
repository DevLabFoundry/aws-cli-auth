package credentialexchange_test

import (
	"fmt"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/dnitsch/aws-cli-auth/internal/credentialexchange"
	ini "gopkg.in/ini.v1"
)

// Tests need fixing up a bit
func TestGetEntryInIni(t *testing.T) {
	cfg, err := ini.Load("../../.aws-cli-auth.ini")
	if err != nil {
		t.Fatalf("Fail to read file: %v", err)
	}
	section := cfg.Section("role")
	roles := section.ChildSections()

	if len(roles) != 2 {
		t.Errorf("Incorrectly parsed INI got %d, wanted: 2", len(roles))
	}
}

func TestCreateEntryInIni(t *testing.T) {
	cfg, err := ini.Load("../../.aws-cli-auth.ini")

	if err != nil {
		t.Fatalf("Fail to read file: %v", err)
	}

	section := cfg.Section(credentialexchange.INI_CONF_SECTION) //
	if !cfg.HasSection(fmt.Sprintf("%s.%s", credentialexchange.INI_CONF_SECTION, credentialexchange.RoleKeyConverter(roleTest))) {
		t.Errorf("section NOT Exists")
	}
	roles := section.ChildSections()
	subSectionExists := false
	for _, v := range roles {
		if v.Name() == fmt.Sprintf("role.%s", credentialexchange.RoleKeyConverter(roleTest)) {
			subSectionExists = true
			break
		}
	}

	if !subSectionExists {
		t.Errorf("Not found nothing to do")
	}
}

func TestReloadBeforeExpirySuccess(t *testing.T) {

	expiry := (time.Now()).Add(time.Second * 305)

	got := credentialexchange.ReloadBeforeExpiry(expiry, 300)

	if got {
		t.Errorf("Expected %v, got: %v", false, got)
	}
}

func TestReloadBeforeExpiryNeedToRefresh(t *testing.T) {

	expiry := (time.Now()).Add(time.Second * 299)

	got := credentialexchange.ReloadBeforeExpiry(expiry, 300)

	if !got {
		t.Errorf("Expected %v, got: %v", false, got)
	}
}

func Test_HomeDirOverwritten(t *testing.T) {
	ttests := map[string]struct {
		setUpCleanUp func() func()
	}{
		"test1": {
			setUpCleanUp: func() func() {
				orignalEnv := os.Environ()
				os.Setenv("HOME", "./.ignore-delete")
				return func() {
					for _, e := range orignalEnv {
						pair := strings.SplitN(e, "=", 2)
						os.Setenv(pair[0], pair[1])
					}
				}
			},
		},
	}
	for name, tt := range ttests {
		t.Run(name, func(t *testing.T) {
			cleanUp := tt.setUpCleanUp()
			defer cleanUp()
			got := credentialexchange.HomeDir()
			if got != "./.ignore-delete" {
				t.Fail()
			}
		})
	}
}

func Test_InsertIntoRoleSlice_with(t *testing.T) {
	ttests := map[string]struct {
		role      string
		roleChain []string
		expect    []string
	}{
		"chain empty and role specified": {
			"role", []string{}, []string{"role"},
		},
		"chain set and role empty": {
			"", []string{"rolec1"}, []string{"rolec1"},
		},
		"both set and role is always first in list": {
			"role", []string{"rolec1"}, []string{"role", "rolec1"},
		},
	}
	for name, tt := range ttests {
		t.Run(name, func(t *testing.T) {
			if got := credentialexchange.InsertRoleIntoChain(tt.role, tt.roleChain); len(got) != len(tt.expect) {
				t.Errorf("expected: %v, got: %v", tt.expect, got)
			}
		})
	}
}

func Test_SetCredentials_with(t *testing.T) {
	ttests := map[string]struct {
		setup     func() func()
		conf      credentialexchange.CredentialConfig
		cred      func() *credentialexchange.AWSCredentials
		expectErr bool
	}{
		"write to creds file": {
			setup: func() func() {
				tempDir, _ := os.MkdirTemp(os.TempDir(), "set-creds-tester")
				os.Setenv("HOME", tempDir)
				return func() {
					os.Clearenv()
					os.RemoveAll(tempDir)
				}
			},
			cred: func() *credentialexchange.AWSCredentials {
				return mockSuccessCreds
			},
			conf: credentialexchange.CredentialConfig{
				BaseConfig: credentialexchange.BaseConfig{
					StoreInProfile: true,
					CfgSectionName: "test-section",
				},
			},
		},
		"write to stdout": {
			setup: func() func() {
				tempDir, _ := os.MkdirTemp(os.TempDir(), "set-creds-tester")
				os.Setenv("HOME", tempDir)
				return func() {
					os.Clearenv()
					os.RemoveAll(tempDir)
				}
			},
			cred: func() *credentialexchange.AWSCredentials {
				return mockSuccessCreds
			},
			conf: credentialexchange.CredentialConfig{
				BaseConfig: credentialexchange.BaseConfig{
					StoreInProfile: false,
					CfgSectionName: "test-section",
				},
			},
		},
		"write using AWS_CREDENTIALS_FILE": {
			setup: func() func() {
				tempDir, _ := os.MkdirTemp(os.TempDir(), "set-creds-tester")
				os.Setenv("HOME", tempDir)
				os.WriteFile(path.Join(tempDir, "creds"), []byte(``), 0777)
				os.Setenv("AWS_SHARED_CREDENTIALS_FILE", path.Join(tempDir, "creds"))
				return func() {
					os.Clearenv()
					os.RemoveAll(tempDir)
				}
			},
			cred: func() *credentialexchange.AWSCredentials {
				return mockSuccessCreds
			},
			conf: credentialexchange.CredentialConfig{
				BaseConfig: credentialexchange.BaseConfig{
					StoreInProfile: true,
					CfgSectionName: "test-section",
				},
			},
		},
		// "fail on marshal to stdout": {
		// 	setup: func() func() {
		// 		tempDir, _ := os.MkdirTemp(os.TempDir(), "set-creds-tester")
		// 		os.Setenv("HOME", tempDir)
		// 		os.WriteFile(path.Join(tempDir, "creds"), []byte(``), 0777)
		// 		os.Setenv("AWS_SHARED_CREDENTIALS_FILE", path.Join(tempDir, "creds"))
		// 		return func() {
		// 			os.Clearenv()
		// 			os.RemoveAll(tempDir)
		// 		}
		// 	},
		// 	cred: func() *credentialexchange.AWSCredentials {
		// 		var x interface{}
		// 		x = &credentialexchange.AWSCredentials{}
		// 		cred := &credentialexchange.AWSCredentials{
		// 			PrincipalARN: x,
		// 		}
		// 		return cred
		// 	},
		// 	conf: credentialexchange.CredentialConfig{
		// 		BaseConfig: credentialexchange.BaseConfig{
		// 			StoreInProfile: true,
		// 			CfgSectionName: "test-section",
		// 		},
		// 	},
		// 	expectErr: true,
		// },
	}
	for name, tt := range ttests {
		t.Run(name, func(t *testing.T) {
			cleanUp := tt.setup()

			defer cleanUp()

			err := credentialexchange.SetCredentials(tt.cred(), tt.conf)
			if tt.expectErr && err == nil {
				t.Error("got <nil>, wanted non nil")
				return
			}

			if err != nil {
				t.Errorf("got %s, wanted <nil>", err)
			}
		})
	}
}
