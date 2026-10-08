# plugin-auth-backend-module-microsoft-certificate-provider

A Backstage auth backend module that provides a Microsoft/Entra ID OAuth
provider authenticating as a **confidential client with a certificate**
(`private_key_jwt`, RFC 7523) instead of a `clientSecret`.

The stock `@backstage/plugin-auth-backend-module-microsoft-provider` only
supports `client_secret` - its `passport-microsoft`/`passport-oauth2`
dependency chain hardcodes `client_secret` in every token request and has no
hook for a signed JWT assertion. This module re-implements the authorization
code flow directly against Entra ID's `/oauth2/v2.0/{authorize,token}`
endpoints, swapping the secret for a certificate-signed assertion, while
keeping the rest of the behavior (profile shape, sign-in resolvers, scope
handling) compatible with the stock provider.

Do not install this module alongside the official `microsoft-provider`
module - both register the `microsoft` provider id and will conflict.

## How it works

- `src/clientAssertion.ts` - computes the certificate's SHA-1 thumbprint
  (`x5t`) and signs the JWT client assertion with the private key.
- `src/tokenClient.ts` - talks to the `/authorize` and `/token` endpoints
  directly, sending `client_assertion`/`client_assertion_type` instead of
  `client_secret`.
- `src/graphProfile.ts` - fetches the signed-in user's profile (and photo)
  from Microsoft Graph, normalized into the same shape `passport-microsoft`
  produces, so it's compatible with `src/resolvers.ts` and Backstage's
  default profile transform.
- `src/authenticator.ts` - wires the above into Backstage's
  `createOAuthAuthenticator` contract (`start`/`authenticate`/`refresh`).
- `src/module.ts` - registers it as the `microsoft` auth provider via
  `createBackendModule`.

## 1. Generate a certificate

Any certificate Entra ID will accept works; a self-signed one is fine, since
only the public certificate is uploaded to Entra ID and only used there to
verify your signed assertions:

```sh
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 730 -nodes -subj "/CN=backstage-auth"
```

Entra ID requires an RSA key of at least 2048 bits. Convert the private key
to an unencrypted PKCS8 PEM if it isn't already one (this module doesn't
support passphrase-protected keys - keep the file permissions locked down
instead):

```sh
openssl pkcs8 -topk8 -nocrypt -in key.pem -out key.pkcs8.pem
```

## 2. Upload the certificate to the app registration

In the Entra ID app registration used for Backstage sign-in: **Certificates
& secrets → Certificates → Upload certificate**, and upload `cert.pem`. Only
the public certificate goes to Entra ID - never upload or share
`key.pkcs8.pem`.

## 3. Configure Backstage

```yaml
auth:
  providers:
    microsoft:
      development:
        clientId: ${AUTH_MICROSOFT_CLIENT_ID}
        tenantId: ${AUTH_MICROSOFT_TENANT_ID}
        certificate:
          certificate: ${AUTH_MICROSOFT_CERTIFICATE}
          privateKey: ${AUTH_MICROSOFT_PRIVATE_KEY}
        signIn:
          resolvers:
            - resolver: emailMatchingUserEntityAnnotation
```

Pass the PEM contents as environment variables (e.g. the whole multi-line
PEM string), or load them from your secrets manager at startup - never
commit `key.pkcs8.pem` to the repository.

## 4. Register the module

```ts
// packages/backend/src/index.ts
backend.add(
  import('@internal/plugin-auth-backend-module-microsoft-certificate-provider'),
);
```

## Testing

```sh
npm install
npm test
npm run build
```

Unit tests cover the assertion signing (thumbprint, JWT claims) and the
token client (verifying `client_secret` is never sent and `client_assertion`
is sent instead), using a throwaway fixture certificate committed under
`src/__tests__/fixtures/`. They don't cover an actual round trip against
Entra ID - validate that separately against a real app registration with the
certificate uploaded before relying on this in production.

## Known limitations

- No passphrase support for the private key.
- No certificate rotation helper - when you upload a new certificate before
  the old one expires, update `certificate.certificate`/`certificate.privateKey`
  in config at the same time, or support both via your secrets manager's
  versioning.
