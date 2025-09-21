package credentialexchange_test

import (
	"errors"
	"fmt"
	"os"
	"path"
	"testing"
	"time"

	"github.com/DevLabFoundry/aws-cli-auth/internal/credentialexchange"
	"github.com/werf/lockgate"
	"github.com/zalando/go-keyring"
)

var roleTest string = "arn:aws:iam::111122342343:role/DevAdmin"
var keyTest string = "arn_aws_iam__111122342343_role____DevAdmin"

func TestConvertRoleToKey(t *testing.T) {

	got := credentialexchange.RoleKeyConverter(roleTest)
	want := keyTest
	if got != want {
		t.Errorf("Wanted: %s, Got: %s", want, got)
	}
}

func TestConvertKeyToRole(t *testing.T) {

	got := credentialexchange.KeyRoleConverter(keyTest)
	want := roleTest
	if got != want {
		t.Errorf("Wanted: %s, Got: %s", want, got)
	}
}

type mockKeyRing struct {
	set       func(service, user, password string) error
	get       func(service, user string) (string, error)
	delete    func(service, user string) error
	deleteAll func(service string) error
}

func (m *mockKeyRing) Set(service, user, password string) error {
	return m.set(service, user, password)
}
func (m *mockKeyRing) Get(service, user string) (string, error) {
	return m.get(service, user)
}
func (m *mockKeyRing) Delete(service, user string) error {
	return m.delete(service, user)
}
func (m *mockKeyRing) DeleteAll(service string) error {
	return m.deleteAll(service)
}

type mockLocker struct {
	acquire func(lockName string, opts lockgate.AcquireOptions) (bool, lockgate.LockHandle, error)
	release func(lock lockgate.LockHandle) error
}

func (m *mockLocker) Acquire(lockName string, opts lockgate.AcquireOptions) (bool, lockgate.LockHandle, error) {
	return m.acquire(lockName, opts)
}

func (m *mockLocker) Release(lock lockgate.LockHandle) error {
	return m.release(lock)
}

var mockSuccessCreds = &credentialexchange.AWSCredentials{
	AWSAccessKey:    "12345",
	AWSSecretKey:    "67890",
	AWSSessionToken: "SOME_LONG_TOKEN",
	Expires:         time.Now().Add(time.Duration(10) * time.Minute),
}

func Test_SecretStore_AWSCredential_(t *testing.T) {
	ttests := map[string]struct {
		keyring   func(t *testing.T) keyring.Keyring
		locker    func(t *testing.T) lockgate.Locker
		expect    *credentialexchange.AWSCredentials
		errTyp    error
		expectErr bool
	}{
		"succeeds with correctly retrieved credential": {
			keyring: func(t *testing.T) keyring.Keyring {
				k := &mockKeyRing{}
				k.get = func(service, user string) (string, error) {
					return fmt.Sprintf(`{"AccessKeyId":"12345","SecretAccessKey":"67890","SessionToken":"SOME_LONG_TOKEN","Expiration":"%v"}`, mockSuccessCreds.Expires.Format("2006-01-02T15:04:05.000Z")), nil
				}
				return k
			},
			locker: func(t *testing.T) lockgate.Locker {
				l := &mockLocker{}
				l.acquire = func(lockName string, opts lockgate.AcquireOptions) (bool, lockgate.LockHandle, error) {
					return true, lockgate.LockHandle{UUID: "123123321dsdd", LockName: "somename"}, nil
				}
				l.release = func(lock lockgate.LockHandle) error {
					return nil
				}
				return l
			},
			expect:    mockSuccessCreds,
			errTyp:    nil,
			expectErr: false,
		},
		"succeeds with not found on keychain": {
			keyring: func(t *testing.T) keyring.Keyring {
				k := &mockKeyRing{}
				k.get = func(service, user string) (string, error) {
					return "", fmt.Errorf("some err %w", keyring.ErrNotFound)
				}
				k.set = func(service, user, password string) error {
					return nil
				}
				return k
			},
			locker: func(t *testing.T) lockgate.Locker {
				l := &mockLocker{}
				l.acquire = func(lockName string, opts lockgate.AcquireOptions) (bool, lockgate.LockHandle, error) {
					return true, lockgate.LockHandle{UUID: "123123321dsdd", LockName: "somename"}, nil
				}
				l.release = func(lock lockgate.LockHandle) error {
					return nil
				}
				return l
			},
			expect:    mockSuccessCreds,
			errTyp:    nil,
			expectErr: false,
		},
	}
	for name, tt := range ttests {
		t.Run(name, func(t *testing.T) {

			tmpDir, _ := os.MkdirTemp(os.TempDir(), "saml-cred-test")
			_ = os.WriteFile(path.Join(tmpDir, fmt.Sprintf(".%s.ini", credentialexchange.SELF_NAME)), []byte(`
[role]
[role.roleArn]
name = "arn:aws:iam::111122342343:role/DevAdmin"
`), 0777)
			os.Setenv("HOME", tmpDir)
			defer func() {
				os.Clearenv()
				os.RemoveAll(tmpDir)
			}()

			crde, err := credentialexchange.NewSecretStore("roleArn", "namer", tmpDir, "test-user")
			if err != nil {
				t.Fail()
			}
			crde.WithKeyring(tt.keyring(t)).WithLocker(tt.locker(t))
			got, err := crde.AWSCredential()
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
				t.Errorf("got %s, wanted <nil>", err)
			}

			if got != nil {
				if got.AWSSessionToken != tt.expect.AWSSessionToken {
					t.Errorf("expected: \n%+v\n\n and got: \n%+v\n\n to be equal", tt.expect, got)
				}
			}
		})
	}
}

func Test_SaveAwsCredential_with(t *testing.T) {
	ttests := map[string]struct {
		keyring   func(t *testing.T) keyring.Keyring
		locker    func(t *testing.T) lockgate.Locker
		cred      *credentialexchange.AWSCredentials
		errTyp    error
		expectErr bool
	}{
		"correct input": {
			keyring: func(t *testing.T) keyring.Keyring {
				k := &mockKeyRing{}
				k.get = func(service, user string) (string, error) {
					return fmt.Sprintf(`{"AccessKeyId":"12345","SecretAccessKey":"67890","SessionToken":"SOME_LONG_TOKEN","Expiration":"%v"}`, mockSuccessCreds.Expires.Format("2006-01-02T15:04:05.000Z")), nil
				}
				k.set = func(service, user, password string) error {
					return nil
				}
				return k
			},
			locker: func(t *testing.T) lockgate.Locker {
				l := &mockLocker{}
				l.acquire = func(lockName string, opts lockgate.AcquireOptions) (bool, lockgate.LockHandle, error) {
					return true, lockgate.LockHandle{UUID: "123123321dsdd", LockName: "somename"}, nil
				}
				l.release = func(lock lockgate.LockHandle) error {
					return nil
				}
				return l
			},
			cred:      mockSuccessCreds,
			errTyp:    nil,
			expectErr: false,
		},
	}
	for name, tt := range ttests {
		t.Run(name, func(t *testing.T) {
			tmpDir, _ := os.MkdirTemp(os.TempDir(), "saml-cred-test")
			iniFile := path.Join(tmpDir, fmt.Sprintf(".%s.ini", credentialexchange.SELF_NAME))
			_ = os.WriteFile(iniFile, []byte(`
[role]
[role.someotherRole]
name = "arn:aws:iam::111122342343:role/DevAdmin"
`), 0777)
			os.Setenv("HOME", tmpDir)
			defer func() {
				os.Clearenv()
				os.RemoveAll(tmpDir)
			}()

			crde, errInit := credentialexchange.NewSecretStore("roleArn", "namer", tmpDir, "test-user")

			if errInit != nil {
				t.Fatal(errInit)
				return
			}

			crde.WithKeyring(tt.keyring(t)).WithLocker(tt.locker(t))

			err := crde.SaveAWSCredential(tt.cred)

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
				t.Errorf("got %s, wanted <nil>", err)
			}

		})
	}
}

func Test_ClearAll_with(t *testing.T) {
	ttests := map[string]struct {
		keyring   func(t *testing.T) keyring.Keyring
		locker    func(t *testing.T) lockgate.Locker
		errTyp    error
		expectErr bool
	}{
		"correct input": {
			keyring: func(t *testing.T) keyring.Keyring {
				k := &mockKeyRing{}
				k.delete = func(service, user string) error {
					return nil
				}
				return k
			},
			locker: func(t *testing.T) lockgate.Locker {
				l := &mockLocker{}
				return l
			},
			errTyp:    nil,
			expectErr: false,
		},
		"keyring delete error": {
			keyring: func(t *testing.T) keyring.Keyring {
				k := &mockKeyRing{}
				k.delete = func(service, user string) error {
					return fmt.Errorf("someerror")
				}
				return k
			},
			locker: func(t *testing.T) lockgate.Locker {
				l := &mockLocker{}
				return l
			},
			errTyp:    credentialexchange.ErrFailedToClearSecretStorage,
			expectErr: true,
		},
	}
	for name, tt := range ttests {
		t.Run(name, func(t *testing.T) {
			tmpDir, _ := os.MkdirTemp(os.TempDir(), "saml-cred-test")
			iniFile := path.Join(tmpDir, fmt.Sprintf(".%s.ini", credentialexchange.SELF_NAME))
			_ = os.WriteFile(iniFile, []byte(`
[role]
[role.someotherRole]
name = "arn:aws:iam::111122342343:role/DevAdmin"
`), 0777)
			os.Setenv("HOME", tmpDir)
			defer func() {
				os.Clearenv()
				os.RemoveAll(tmpDir)
			}()

			crde, errInit := credentialexchange.NewSecretStore("roleArn", "namer", tmpDir, "test-user")

			if errInit != nil {
				t.Fatal(errInit)
				return
			}

			crde.WithKeyring(tt.keyring(t)).WithLocker(tt.locker(t))

			err := crde.ClearAll()

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
				t.Errorf("got %s, wanted <nil>", err)
			}

		})
	}
}
