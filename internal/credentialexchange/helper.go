package credentialexchange

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path"
	"strings"
	"time"

	"dario.cat/mergo"
	ini "gopkg.in/ini.v1"
)

var (
	ErrSectionNotFound = errors.New("section not found")
	ErrConfigFailure   = errors.New("config error")
)

const (
	awsAccessKeySection    = "aws_access_key_id"
	awsSecretKeyIdSection  = "aws_secret_access_key"
	awsSessionTokenSection = "aws_session_token"
)

func HomeDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatal("unable to get the user home dir")
	}
	return home
}

// ConfigIniFile returns the ini file if specified a path or default one
// located in `~/.aws-cli-auth.ini`
func ConfigIniFile(basePath string) string {
	if basePath != "" {
		return basePath
	}
	return path.Join(HomeDir(), fmt.Sprintf(".%s.ini", SELF_NAME))
}

func SessionName(username, selfName string) string {
	return fmt.Sprintf("%s-%s", strings.ReplaceAll(username, `\`, "--"), selfName)
}

// MergeRoleChain inserts the main role into the role chain.
//
// This is mainly used with AWS SSO flow where
// the SSO user credentials are used to assume the target role(s).
func MergeRoleChain(role string, roleChain []string, insertRoleIntoChain bool) []string {
	// IF role is provided it can be assumed from the WEB_ID credentials
	// this is to maintain the old implementation
	if insertRoleIntoChain {
		if role != "" {
			return append([]string{role}, roleChain...)
		}
		return roleChain
	}
	return roleChain
}

func SetCredentials(creds *AWSCredentials, config CredentialConfig) error {
	if config.BaseConfig.StoreInProfile {
		if err := storeCredentialsInProfile(*creds, config.BaseConfig.CfgSectionName); err != nil {
			return err
		}
		return nil
	}
	return returnStdOutAsJson(*creds)
}

// GetWebIdTokenFileContents reads the contents of the `AWS_WEB_IDENTITY_TOKEN_FILE` environment variable.
// Used only with specific assume
func GetWebIdTokenFileContents() (string, error) {
	// var content *string
	file, exists := os.LookupEnv(WEB_ID_TOKEN_VAR)
	if !exists {
		return "", fmt.Errorf("fileNotPresent: %s, %w", WEB_ID_TOKEN_VAR, ErrMissingEnvVar)
	}
	content, err := os.ReadFile(file)
	if err != nil {
		return "", err
	}
	return string(content), nil
}

// ReloadBeforeExpiry returns true if the time
// to expiry is less than the specified time in seconds
// false if there is more than required time in seconds
// before needing to recycle credentials
func ReloadBeforeExpiry(expiry time.Time, reloadBeforeSeconds int) bool {
	now := time.Now().Local()
	diff := expiry.Local().Sub(now)
	return diff.Seconds() < float64(reloadBeforeSeconds)
}

// EnsureParentSections guarantees that every dotted child section in the file
// (e.g. [config.foo] or [role.my-role]) has an explicit parent section.
// gopkg.in/ini.v1 does not auto-create parent sections, so HasSection("config")
// returns false when only [config.foo] is present, breaking child-section
// lookups. Calling this once after ini.Load normalises the file in memory
// without touching the file on disk.
func EnsureParentSections(cfg *ini.File) {
	for _, s := range cfg.Sections() {
		if idx := strings.LastIndex(s.Name(), "."); idx > 0 {
			parent := s.Name()[:idx]
			if !cfg.HasSection(parent) {
				_, _ = cfg.NewSection(parent)
			}
		}
	}
}

func LoadCliConfig(cfg *ini.File, cfgSection string) (*CredentialConfig, error) {
	if cfg.HasSection(INI_CONFIG_SECTION) {
		configSection, err := cfg.GetSection(INI_CONFIG_SECTION)
		if err != nil {
			return nil, err
		}
		mainBaseConfig := &BaseConfig{}
		mainConfig := &CredentialConfig{}
		_ = configSection.MapTo(mainConfig)
		_ = configSection.MapTo(mainBaseConfig)
		for _, section := range configSection.ChildSections() {
			if fmt.Sprintf("%s.%s", INI_CONFIG_SECTION, cfgSection) == section.Name() {
				sectionBaseConfig := &BaseConfig{}
				sectionConfig := &CredentialConfig{}
				_ = section.MapTo(sectionConfig)
				_ = section.MapTo(sectionBaseConfig)
				_ = mergo.Merge(mainBaseConfig, sectionBaseConfig, mergo.WithOverride)
				_ = mergo.Merge(mainConfig, sectionConfig, mergo.WithOverride)
				mainConfig.BaseConfig = *mainBaseConfig
				break
			}
		}
		return mainConfig, nil
	}
	return &CredentialConfig{}, nil
}

// WriteIniSection update ini sections in own config file
func WriteIniSection(role string) error {
	section := fmt.Sprintf("%s.%s", INI_ROLE_SECTION, RoleKeyConverter(role))
	cfg, err := ini.Load(ConfigIniFile(""))
	if err != nil {
		return fmt.Errorf("fail to read Ini file: %v, %w", err, ErrConfigFailure)
	}
	if !cfg.HasSection(section) {
		sct, err := cfg.NewSection(section)
		if err != nil {
			return err
		}
		sct.Key("name").SetValue(role)
		return cfg.SaveTo(ConfigIniFile(""))
	}

	return nil
}

func storeCredentialsInProfile(creds AWSCredentials, configSection string) error {
	basePath := path.Join(HomeDir(), ".aws")
	awsConfPath := path.Join(basePath, "credentials")

	if _, err := os.Stat(basePath); os.IsNotExist(err) {
		if err := os.Mkdir(basePath, 0755); err != nil {
			return err
		}
		if err := os.WriteFile(awsConfPath, []byte(``), 0755); err != nil {
			return err
		}
	}

	if overriddenpath, exists := os.LookupEnv("AWS_SHARED_CREDENTIALS_FILE"); exists {
		awsConfPath = overriddenpath
	}

	cfg, err := ini.Load(awsConfPath)
	if err != nil {
		return err
	}
	cfg.Section(configSection).Key(awsAccessKeySection).SetValue(creds.AWSAccessKey)
	cfg.Section(configSection).Key(awsSecretKeyIdSection).SetValue(creds.AWSSecretKey)
	cfg.Section(configSection).Key(awsSessionTokenSection).SetValue(creds.AWSSessionToken)
	return cfg.SaveTo(awsConfPath)
}

func returnStdOutAsJson(creds AWSCredentials) error {
	creds.Version = 1

	jsonBytes, err := json.Marshal(creds)
	if err != nil {
		// Errorf("Unexpected AWS credential response")
		return err
	}
	_, _ = fmt.Fprint(os.Stdout, string(jsonBytes))
	return nil
}
