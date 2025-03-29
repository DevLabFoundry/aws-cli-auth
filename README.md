[![Go Report Card](https://goreportcard.com/badge/github.com/DevLabFoundry/aws-cli-auth)](https://goreportcard.com/report/github.com/DevLabFoundry/aws-cli-auth)
[![Bugs](https://sonarcloud.io/api/project_badges/measure?project=dnitsch_aws-cli-auth&metric=bugs)](https://sonarcloud.io/summary/new_code?id=dnitsch_aws-cli-auth)
[![Technical Debt](https://sonarcloud.io/api/project_badges/measure?project=dnitsch_aws-cli-auth&metric=sqale_index)](https://sonarcloud.io/summary/new_code?id=dnitsch_aws-cli-auth)
[![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=dnitsch_aws-cli-auth&metric=reliability_rating)](https://sonarcloud.io/summary/new_code?id=dnitsch_aws-cli-auth)
[![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=dnitsch_aws-cli-auth&metric=vulnerabilities)](https://sonarcloud.io/summary/new_code?id=dnitsch_aws-cli-auth)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=dnitsch_aws-cli-auth&metric=coverage)](https://sonarcloud.io/summary/new_code?id=dnitsch_aws-cli-auth)

# AWS CLI AUTH

CLI tool for retrieving AWS temporary credentials using a variety of methods.

**Supports**:

- Any IdP Provider SAML provider via WebUI
- AWS Portal direct account => role selection
- Role chaining for every credential exchange type
- web_identity_token file with role chaining

This tool deals with IdP logins via SAML, both into an AWS account directly or via AWS SSO Portal

---
> **NOTE**: [aws cli](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/sso/login.html) now supports a login via a session into a single AWS portal, it works in a similar fashion except this tool does not store the refreshToken on the device and is meant to be used with `credential_process`

---

> If you have an OIDC IdP provider set up to AWS you can use this [aws-cli-oidc](https://github.com/openstandia/aws-cli-oidc) and likewise this [saml2aws](https://github.com/Versent/saml2aws) for standard SAML only AWS integrations - standard meaning that your IdP has a standard and flow and a supports programatic MFA submission.

If, however, you need to support a non standard user journeys enforced by your IdP i.e. a sub company selection within your organization login portal, or a selection screen for different MFA providers - PingID or RSA HardToken etc.... you cannot reliably automate the flow or it would have to be too specific.

As such this approach uses [go-rod](https://github.com/go-rod/rod) library to uniformly allow the user to complete any and all auth steps and selections in a managed browser session up to the point of where the SAMLResponse is to be sent to AWS ACS service `https://signin.aws.amazon.com/saml`. 

Capturing this via hijack request and posting to AWS STS service to exchange this for the temporary credentials.

The advantage of using SAML is that real users can gain access to the AWS Console UI or programatically and audited as the same person in cloudtrail.

By default the tool creates the session name - which can be audited including the persons username from the localhost.

## [Installation](./docs/install.md)

## [Usage](./docs/usage.md)

## Known Issues

- Even though a datadir is created to store the chromium session data it is advised to still open settings and save the username/password manually the first time you are presented with the login screen.

- Some login forms if not done correctly according to chrome specs and do not specify `type` on the HTML tag with `username` Chromium will not pick it up

- As the process of re-requesting new credentials is **by design** and should be used in places where it cannot be automated - it is good idea **IF POSSIBLE** to use longer sessions for ***NON LIVE*** AWS accounts so that the prompt is not too frequent.

- Prior to `v0.8.0` you might be need to manually kill the `aws-cli-auth` process manually from your OS's process manager.

## Contribute

Contributions to the aws-auth-cli package are most welcome from engineers of all backgrounds and skill levels. 

In particular the addition of extra test coverage, code enhacements.

This project will adhere to the [Go Community Code of Conduct](https://go.dev/conduct) in the github provided discussion spaces.

To make a contribution:

- Fork the repository
- Make your changes on the fork
- Submit a pull request back to this repo with a clear description of the problem you're solving
- Ensure your PR passes all current (and new) tests

## Acknowledgements

Inspired by/Borrowed the design for secretStore from these 2 packages:

- [Hiroyuki Wada](https://github.com/wadahiro) [package](https://github.com/openstandia/aws-cli-oidc) 
- [Mark Wolfe](https://github.com/wolfeidau) [package](https://github.com/Versent/saml2aws)
