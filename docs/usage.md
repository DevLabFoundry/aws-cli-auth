
# Usage

```
CLI tool for retrieving AWS temporary credentials using SAML providers, or specified method of retrieval - i.e. force AWS_WEB_IDENTITY.
Useful in situations like CI jobs or containers where multiple env vars might be present.
Stores them under the $HOME/.aws/credentials file under a specified path or returns the crednetial_process payload for use in config

Usage:
  aws-cli-auth [command]

Available Commands:
  aws-cli-auth Clears any stored credentials in the OS secret store
  completion   Generate the autocompletion script for the specified shell
  help         Help about any command
  saml         Get AWS credentials and out to stdout
  specific     Initiates a specific crednetial provider [WEB_ID]

Flags:
      --cfg-section string   config section name in the yaml config file
  -h, --help                 help for aws-cli-auth
  -r, --role string          Set the role you want to assume when SAML or OIDC process completes
  -s, --store-profile        By default the credentials are returned to stdout to be used by the credential_process. Set this flag to instead store the credentials under a named profile section

Use "aws-cli-auth [command] --help" for more information about a command.
```

## SAML

```
Get AWS credentials and out to stdout through your SAML provider authentication.

Usage:
  aws-cli-auth saml <SAML ProviderUrl> [flags]

Flags:
  -a, --acsurl string              Override the default ACS Url, used for checkin the post of the SAMLResponse (default "https://signin.aws.amazon.com/saml")
      --executable-path string     Custom path to an executable
                                   
                                   This needs to be a chromium like executable - e.g. Chrome, Chromium, Brave, Edge. 
                                   
                                   You can find out the path by opening your browser and typing in chrome|brave|edge://version
                                   
  -h, --help                       help for saml
      --is-sso                     Enables the new AWS User portal login. 
                                   If this flag is specified the --sso-role must also be specified.
      --principal string           Principal Arn of the SAML IdP in AWS
                                   You should find it in the IAM portal e.g.: arn:aws:iam::1234567891012:saml-provider/MyCompany-Idp
                                   
  -p, --provider string            Saml Entity StartSSO Url.
                                   This is the URL your Idp will make the first call to e.g.: https://company-xyz.okta.com/home/amazon_aws/12345SomeRandonId6789
                                   
      --reload-before int          Triggers a credentials refresh before the specified max-duration. Value provided in seconds. Should be less than the max-duration of the session
  -r, --role string                Set the role you want to assume when SAML or OIDC process completes
      --saml-timeout int32         Timeout in seconds, before the operation of waiting for a response is cancelled via the chrome driver (default 120)
      --sso-fed-endpoint string    FederationCredEndpoint in a go style fmt.Sprintf string with a region placeholder (default "https://portal.sso.%s.amazonaws.com/federation/credentials/")
      --sso-region string          If using SSO, you must set the region (default "eu-west-1")
      --sso-role string            Sso Role name must be in this format - 12345678910:PowerUser
      --sso-user-endpoint string   UserEndpoint in a go style fmt.Sprintf string with a region placeholder (default "https://portal.sso.%s.amazonaws.com/user")

Global Flags:
      --cfg-section string   Config section name in the default AWS credentials file. To enable priofi
  -d, --max-duration int     Override default max session duration, in seconds, of the role session [900-43200]. 
                             NB: This cannot be higher than the 3600 as the API does not allow for AssumeRole for sessions longer than an hour (default 900)
      --role-chain strings   If specified it will assume the roles from the base credentials, in order they are specified in
  -s, --store-profile        By default the credentials are returned to stdout to be used by the    
  
                              credential_process. 
                              Set this flag to instead store the credentials under a named profile section. You can then reference that profile name via the CLI or for use in an SDK
  -v, --verbose              Verbose output
```

Example:

```bash
aws-cli-auth saml --cfg-section nonprod_saml_admin -p "https://your-idp.com/idp/foo?PARTNER=urn:amazon:webservices" --principal "arn:aws:iam::XXXXXXXXXX:saml-provider/IDP_ENTITY_ID" -r "arn:aws:iam::XXXXXXXXXX:role/Developer" -d 3600 -s
```

The PartnerId in most IdPs is usually `urn:amazon:webservices` - but you can change this for anything you stored it as.

If successful will store the creds under the specified config section in credentials profile as per below example

```ini
[default]
aws_access_key_id     = XXXXX
aws_secret_access_key = YYYYYYYYY

[another_profile]
aws_access_key_id     = XXXXX
aws_secret_access_key = YYYYYYYYY

[nonprod_saml_admin]
aws_access_key_id     = XXXXXX
aws_secret_access_key = YYYYYYYYY
aws_session_token     = ZZZZZZZZZZZZZZZZZZZZ
```

To give it a quick test.

```bash
aws sts get-caller-identity --profile=nonprod_saml_admin
```

## AWS SSO Portal

**NOW** Includes support for AWS User Portal, largely remains the same with a few exceptions/additions:

- `-r|--role`
  needs to be in the following format `12345678901:AdministratorAccess`
- `--sso-region`
  region of your SSO setup
- `--is-sso`
  flag to set the flow over AWS SSO

Sample: `aws-cli-auth saml --cfg-section test_sso_portal -p https://your_idp.com/app_id -r 12345678901:AdministratorAccess --sso-region ap-north-1 -d 3600 --is-sso --reload-before 60`

## AWS Credential Process

[Sourcing credentials with an external process](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html) describes how to integrate aws-cli with external tool.
You can use `aws-cli-auth` as the external process. Add the following lines to your `.aws/config` file.

```
[profile test_nonprod]
region = eu-west-1
credential_process=aws-cli-auth saml -p https://your-idp.com/idp/foo?PARTNER=urn:amazon:webservices --principal arn:aws:iam::XXXXXXXXXX:saml-provider/IDP_ENTITY_ID -r arn:aws:iam::XXXXXXXXXX:role/Developer -d 3600
```

Optionally you can still use it as a source profile provided your base role allows AssumeRole on that resource

```
[profile elevated_from_test_nonprod]
role_arn = arn:aws:iam::XXXXXXXXXX:role/ElevatedRole
source_profile = test_nonprod
region = eu-west-1
output = json
```

Notice the missing `-s` | `--store-profile` flag

## Use in CI

Often times in CI you may have multiple credential provider methods enabled for various flows - this method lets you specify the exact credential provider to use without removing environment variables.

```
Initiates a specific crednetial provider [WEB_ID] as opposed to relying on the defaultCredentialChain provider.
This is useful in CI situations where various authentication forms maybe present from AWS_ACCESS_KEY as env vars to metadata of the node.
Returns the same JSON object as the call to the AWS cli for any of the sts AssumeRole* commands

Usage:
  aws-cli-auth specific <flags> [flags]

Flags:
  -h, --help            help for specific
  -m, --method string   Runs a specific credentialProvider as opposed to rel (default "WEB_ID")

Global Flags:
      --cfg-section string   config section name in the yaml config file
  -r, --role string          Set the role you want to assume when SAML or OIDC process completes
  -s, --store-profile        By default the credentials are returned to stdout to be used by the credential_process. Set this flag to instead store the credentials under a named profile section
```

```bash
AWS_ROLE_ARN=arn:aws:iam::XXXX:role/some-role-in-k8s-service-account AWS_WEB_IDENTITY_TOKEN_FILE=/var/token aws-cli-auth specific | jq .
```

Above is the same as this:

```bash
AWS_ROLE_ARN=arn:aws:iam::XXXX:role/some-role-in-k8s-service-account AWS_WEB_IDENTITY_TOKEN_FILE=/var/token aws-cli-auth specific -m WEB_ID | jq .
```

## Clear

```
Clears any stored credentials in the OS secret store

Usage:
  aws-cli-auth clear-cache <flags> [flags]

Flags:
  -f, --force   If aws-cli-auth exited improprely in a previous run there is a chance that there could be hanging processes left over - this will clean them up forcefully
  -h, --help    help for clear-cache

Global Flags:
      --cfg-section string   config section name in the yaml config file
  -r, --role string          Set the role you want to assume when SAML or OIDC process completes
  -s, --store-profile        By default the credentials are returned to stdout to be used by the credential_process. Set this flag to instead store the credentials under a named profile section
```
