package credentialexchange

import (
	"encoding/json"
	"fmt"
	"time"
)

const (
	SELF_NAME        = "aws-cli-auth"
	WEB_ID_TOKEN_VAR = "AWS_WEB_IDENTITY_TOKEN_FILE"
	AWS_ROLE_ARN     = "AWS_ROLE_ARN"
	INI_CONF_SECTION = "role"
)

type BaseConfig struct {
	Role                  string   `ini:"role"`
	RoleChain             []string `ini:"role-chain"`
	BrowserExecutablePath string   `ini:"browser-executable-path"`
	Username              string
	CfgSectionName        string
	StoreInProfile        bool
	ReloadBeforeTime      int
}

type CredentialConfig struct {
	BaseConfig         BaseConfig
	ProviderUrl        string `ini:"provider-url"`
	PrincipalArn       string `ini:"principal"`
	AcsUrl             string
	Duration           int    `ini:"duration"`
	IsSso              bool   `ini:"is-sso"`
	SsoRegion          string `ini:"sso-region"`
	SsoRole            string `ini:"sso-role"`
	SsoUserEndpoint    string `ini:"is-sso-endpoint"`
	SsoCredFedEndpoint string
}

// AWSRole aws role attributes
type AWSRoleConfig struct {
	RoleARN      string
	PrincipalARN string
	Name         string
}

// AWSCredentials is a representation of the returned credential
type AWSCredentials struct {
	Version         int
	AWSAccessKey    string    `json:"AccessKeyId"`
	AWSSecretKey    string    `json:"SecretAccessKey"`
	AWSSessionToken string    `json:"SessionToken"`
	PrincipalARN    string    `json:"-"`
	Expires         time.Time `json:"Expiration"`
}

// roleCreds can be encapsulated in this function
// never used outside of this scope for now
type roleCreds struct {
	RoleCreds struct {
		AccessKey    string `json:"accessKeyId"`
		SecretKey    string `json:"secretAccessKey"`
		SessionToken string `json:"sessionToken"`
		Expiration   int64  `json:"expiration"`
	} `json:"roleCredentials"`
}

func (a *AWSCredentials) FromRoleCredString(cred string) (*AWSCredentials, error) {
	rc := &roleCreds{}
	if err := json.Unmarshal([]byte(cred), rc); err != nil {
		return nil, fmt.Errorf("%s, %w", err, ErrUnmarshalCred)
	}
	a.AWSAccessKey = rc.RoleCreds.AccessKey
	a.AWSSecretKey = rc.RoleCreds.SecretKey
	a.AWSSessionToken = rc.RoleCreds.SessionToken
	a.Expires = time.UnixMilli(rc.RoleCreds.Expiration)
	return a, nil
}
