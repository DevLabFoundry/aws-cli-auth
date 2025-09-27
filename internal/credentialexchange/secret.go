package credentialexchange

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/werf/lockgate"
	"github.com/werf/lockgate/pkg/file_locker"
	"github.com/zalando/go-keyring"
	ini "gopkg.in/ini.v1"
)

var (
	ErrUnableToLoadAWSCred        = errors.New("unable to laod AWS credential")
	ErrCannotLockDir              = errors.New("unable to create lock dir")
	ErrUnableToRetrieveSections   = errors.New("unable to retrieve sections")
	ErrUnableToLoadDueToLock      = errors.New("cannot load secret due to lock error")
	ErrUnableToAcquireLock        = errors.New("cannot acquire lock")
	ErrUnmarshallingSecret        = errors.New("cannot unmarshal secret")
	ErrFailedToClearSecretStorage = errors.New("failed to clear secret storage on OS")
)

// AWSRole aws role attributes
type AWSRole struct {
	RoleARN      string
	PrincipalARN string
	Name         string
	Duration     int
}

// SecretStore
type SecretStore struct {
	AWSCredentials *AWSCredentials
	AWSCredJson    string
	keyring        keyring.Keyring
	roleArn        string
	lockDir        string
	locker         lockgate.Locker
	lockResource   string
	secretService  string
	secretUser     string
}

func (s *SecretStore) WithLocker(locker lockgate.Locker) *SecretStore {
	s.locker = locker
	return s
}

func (s *SecretStore) WithKeyring(keyring keyring.Keyring) *SecretStore {
	s.keyring = keyring
	return s
}

// keyRingImpl is the default keyring implementation
type keyRingImpl struct{}

func (k *keyRingImpl) Set(service, user, password string) error {
	return keyring.Set(service, user, password)
}
func (k *keyRingImpl) Get(service, user string) (string, error) {
	return keyring.Get(service, user)
}
func (k *keyRingImpl) Delete(service, user string) error {
	return keyring.Delete(service, user)
}

func (k *keyRingImpl) DeleteAll(service string) error {
	return keyring.DeleteAll(service)
}

func NewSecretStore(roleArn, namer, baseDir, username string) (*SecretStore, error) {
	lockDir := baseDir + "/aws-clie-auth-lock"
	locker, err := file_locker.NewFileLocker(lockDir)
	if err != nil {
		return nil, fmt.Errorf("cannot setup lock dir: %s", lockDir)
	}

	return &SecretStore{
		lockDir:       lockDir,
		locker:        locker,
		keyring:       &keyRingImpl{},
		lockResource:  namer,
		secretService: namer,
		roleArn:       roleArn,
		secretUser:    username,
	}, nil
}

func (s *SecretStore) AWSCredential() (*AWSCredentials, error) {
	if err := s.load(); err != nil {
		return nil, fmt.Errorf("secret store: %s, %w", err, ErrUnableToLoadAWSCred)
	}

	if s.AWSCredentials == nil && s.AWSCredJson == "" {
		return nil, nil
	}

	return s.AWSCredentials, nil
}

func (s *SecretStore) SaveAWSCredential(cred *AWSCredentials) error {
	s.AWSCredentials = cred
	jsonStr, err := json.Marshal(cred)
	if err != nil {
		return err
	}
	s.AWSCredJson = string(jsonStr)
	return s.save()
}

// ClearAll loops through all the sections in the INI file
// deletes them from the keychain implementation on the OS
func (s *SecretStore) ClearAll(cfg *ini.File) error {
	srvSections := []string{}

	for _, v := range cfg.Section(INI_CONF_SECTION).ChildSections() {
		srvSections = append(srvSections, strings.ReplaceAll(v.Name(), fmt.Sprintf("%s.", INI_CONF_SECTION), ""))
	}

	for _, v := range srvSections {
		srv := fmt.Sprintf("%s-%s", SELF_NAME, v)
		// fmt.Fprintf(os.Stderr, "username: %s\ncredentialsecret: %s\n", s.secretUser, srv)
		if err := s.keyring.Delete(srv, s.secretUser); err != nil {
			return fmt.Errorf("%s, %w", err, ErrFailedToClearSecretStorage)
		}
	}

	return nil
}

func (s *SecretStore) ensureLock() (func(), error) {

	acquired, lock, err := s.locker.Acquire(s.lockResource, lockgate.AcquireOptions{Shared: false, Timeout: 1 * time.Minute})
	if err != nil {
		return nil, fmt.Errorf("%s, %w", err, ErrUnableToAcquireLock)
	}

	if !acquired {
		return nil, fmt.Errorf("%s, %w", err, ErrUnableToLoadDueToLock)
	}
	return func() {
		if acquired {
			if err := s.locker.Release(lock); err != nil {
				fmt.Fprintf(os.Stderr, "")
			}
		}
	}, nil
}

func (s *SecretStore) load() error {
	release, err := s.ensureLock()
	if err != nil {
		return err
	}
	defer release()

	creds := &AWSCredentials{}

	jsonStr, err := s.keyring.Get(s.secretService, s.secretUser)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return nil
		}
		return err
	}

	if err := json.Unmarshal([]byte(jsonStr), &creds); err != nil {
		return fmt.Errorf("%s, %w", err, ErrUnmarshallingSecret)
	}

	if err := WriteIniSection(s.roleArn); err != nil {
		return err
	}

	s.AWSCredentials = creds
	s.AWSCredJson = jsonStr
	return nil
}

func (s *SecretStore) save() error {
	release, err := s.ensureLock()
	if err != nil {
		return err
	}

	defer release()

	if err := WriteIniSection(s.roleArn); err != nil {
		return err
	}

	return s.keyring.Set(s.secretService, s.secretUser, s.AWSCredJson)
}

// RoleKeyConverter converts a role to a key used for storing in key store
func RoleKeyConverter(role string) string {
	return strings.ReplaceAll(strings.ReplaceAll(role, ":", "_"), "/", "____")
}

// KeyRoleConverter Converts a key back to a role
func KeyRoleConverter(key string) string {
	return strings.ReplaceAll(strings.ReplaceAll(key, "____", "/"), "_", ":")
}
