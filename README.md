# aws-cli-auth

CLI tool for retrieving AWS temporary credentials using SAML providers.

Firstly, this package currently deals with SAML only (OIDC to come), however if you have an OIDC IdP provider set up to AWS you can use this [package](https://github.com/openstandia/aws-cli-oidc) and likewise this [package](https://github.com/Versent/saml2aws) for standard SAML AWS integrations.

If, however, you need to support a non standard user journeys enforced by your IdP i.e. a sub company selection within your organization login portal, or a selection screen for different MFA providers - PingID or RSA HardToken etc.... you cannot reliably automate the flow or it would have to be too specific. 

As such this approach uses [go-rod](https://github.com/go-rod/rod) library to uniformly allow the user to complete any and all auth steps and selections in a managed browser session up to the point of where the SAMLResponse were to be sent to AWS ACS service `https://signin.aws.amazon.com/saml`. Capturing this via hijack request and posting to AWS STS service to exchange this for the temporary credentials.

The advantage of using SAML is that real users can gain access to the AWS Console UI or programatically and audited as the same person in cloudtrail. 

By default the tool creates the session name - which can be audited including the persons username from the localhost.

## Known Issues

- Even though a datadir is created to store the chromium session data it is advised to still open settings and save the username/password manually the first time you are presented with the login screen.

- Some login forms if not done correctly according to chrome specs and do not specify `type` on the HTML tag with `username` Chromium will not pick it up

## Install

Download from [Releases page](https://github.com/dnitsch/aws-cli-auth/releases).

MacOS

```bash
curl -L https://github.com/dnitsch/aws-cli-auth/releases/download/v0.6.0/aws-cli-auth-darwin -o aws-cli-auth
chmod +x aws-cli-auth
sudo mv aws-cli-auth /usr/local/bin
```

Linux
```bash
curl -L https://github.com/dnitsch/aws-cli-auth/releases/download/v0.6.0/aws-cli-auth-linux -o aws-cli-auth
chmod +x aws-cli-auth
sudo mv aws-cli-auth /usr/local/bin
```

Windows
```posh
iwr -Uri "https://github.com/dnitsch/aws-cli-auth/releases/download/v0.6.0/aws-cli-auth-windows.exe" -OutFile "aws-cli-auth"
```


## Usage

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

### SAML 

```
Get AWS credentials and out to stdout through your SAML provider authentication.

Usage:
  aws-cli-auth saml <SAML ProviderUrl> [flags]

Flags:
  -a, --acsurl string      Override the default ACS Url, used for checkin the post of the SAMLResponse (default "https://signin.aws.amazon.com/saml")
  -h, --help               help for saml
  -d, --max-duration int   Override default max session duration, in seconds, of the role session [900-43200] (default 900)
      --principal string   Principal Arn of the SAML IdP in AWS
  -p, --provider string    Saml Entity StartSSO Url

Global Flags:
      --cfg-section string   config section name in the yaml config file
  -r, --role string          Set the role you want to assume when SAML or OIDC process completes
  -s, --store-profile        By default the credentials are returned to stdout to be used by the credential_process
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

### AWS Credential Process

[Sourcing credentials with an external process](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html) describes how to integrate aws-cli with external tool.
You can use `aws-cli-auth` as the external process. Add the following lines to your `.aws/config` file.

```
[profile test_nonprod_iag]
region = eu-west-1
credential_process=aws-cli-auth saml -p https://your-idp.com/idp/foo?PARTNER=urn:amazon:webservices --principal arn:aws:iam::XXXXXXXXXX:saml-provider/IDP_ENTITY_ID -r arn:aws:iam::XXXXXXXXXX:role/Developer -d 3600
```

Notice the missing `-s` | `--store-profile` flag

### Use in CI


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

### Clear

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

## Licence
 WFTPL

## Acknowledgements
  - [Hiroyuki Wada](https://github.com/wadahiro) [package](https://github.com/openstandia/aws-cli-oidc) 
  - [Mark Wolfe](https://github.com/wolfeidau) [package](https://github.com/Versent/saml2aws)
