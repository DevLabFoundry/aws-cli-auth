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

// --cfg-section aws_travelodge_ssvc
// --store-profile
// -p "https://accounts.google.com/o/saml2/initsso?idpid=C03uqod6r&spid=759219486523&forceauthn=false"
// --principal "arn:aws:iam::881490129763:saml-provider/GoogleIdP"
// --role "arn:aws:iam::881490129763:role/IdP-admin"
// --role-chain "arn:aws:iam::881490129763:role/SSO-admin"
// -d 3600
// --reload-before 120
// --executable-path="/Applications/Brave Browser.app/Contents/MacOS/Brave Browser"
