# muggle-OIDC
Demystifying the secrets of OIDC, no magic allowed!

## DISCLAIMER
This application was written to help me understand the details of a specific OIDC flow.
This is NOT a general purpose OIDC client, and such does not support many standard options.
This application skips many steps and does not use any external oauth2/oidc client libraries.
PLEASE USE A REAL LIBRARY WHEN DEVELOPING YOUR OIDC APPLICATION.

**!! THIS APPLICATION SHOULD NOT BE USED FOR ANY OTHER PURPOSE OTHER THAN TESTING AND EDUCATION !!**

## Getting Started
In order for the flow to work you need the following:
- you need to onboard your client with an OIDC provider:
  - `oidc.client_id` must match configuration. `oidc.client_secret` must be present unless using `private_key_jwt`
  - have an external reachable URL when using `private_key_jwt`. jwks URL must be onboarded as `<external_self_baseurl>/api/v1/jwks`
  - redirect URL must be onboarded as `<external_self_baseurl>/api/v1/callback`
- you need to set the `oidc.discovery_url` to the well-known URL of the OIDC provider

**NOTE** the default configuration file is located in: [testdata/sampleconfig/config.yaml](testdata/sampleconfig/config.yaml)

## Begin flow
start your OIDC client server like: `go run cmd/oidc-client/main.go`.
Then navigate to: `<external_self_baseurl>`