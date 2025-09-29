package credentialexchange

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
