import { readFileSync } from 'fs';
import { join } from 'path';
import { decodeJwt, decodeProtectedHeader } from 'jose';
import {
  certificateThumbprint,
  ClientAssertionSigner,
} from '../clientAssertion';

const CERT_PEM = readFileSync(
  join(__dirname, 'fixtures/test-cert.pem'),
  'utf8',
);
const KEY_PEM = readFileSync(
  join(__dirname, 'fixtures/test-key-pkcs8.pem'),
  'utf8',
);

// From `openssl x509 -in test-cert.pem -noout -fingerprint -sha1`
const EXPECTED_SHA1_HEX = 'E80DDB1938908486918B9E9710BDB8514DF18B35';

describe('certificateThumbprint', () => {
  it('computes the base64url SHA-1 thumbprint of the certificate', () => {
    const expected = Buffer.from(EXPECTED_SHA1_HEX, 'hex').toString(
      'base64url',
    );
    expect(certificateThumbprint(CERT_PEM)).toBe(expected);
  });

  it('rejects a non-certificate input', () => {
    expect(() => certificateThumbprint('not a cert')).toThrow(
      /Invalid certificate/,
    );
  });
});

describe('ClientAssertionSigner', () => {
  const signer = new ClientAssertionSigner({
    clientId: 'test-client-id',
    tokenEndpoint: 'https://login.microsoftonline.com/test-tenant/oauth2/v2.0/token',
    certificatePem: CERT_PEM,
    privateKeyPem: KEY_PEM,
  });

  it('signs a JWT with the x5t header set to the certificate thumbprint', async () => {
    const assertion = await signer.sign();
    const header = decodeProtectedHeader(assertion);

    expect(header.alg).toBe('RS256');
    expect(header.typ).toBe('JWT');
    expect(header.x5t).toBe(certificateThumbprint(CERT_PEM));
  });

  it('sets the standard private_key_jwt claims', async () => {
    const assertion = await signer.sign();
    const claims = decodeJwt(assertion);

    expect(claims.iss).toBe('test-client-id');
    expect(claims.sub).toBe('test-client-id');
    expect(claims.aud).toBe(
      'https://login.microsoftonline.com/test-tenant/oauth2/v2.0/token',
    );
    expect(claims.jti).toBeDefined();
    expect(claims.exp).toBeGreaterThan(claims.iat as number);
  });

  it('throws a descriptive error for a malformed private key', async () => {
    const badSigner = new ClientAssertionSigner({
      clientId: 'test-client-id',
      tokenEndpoint: 'https://example.com/token',
      certificatePem: CERT_PEM,
      privateKeyPem: 'not a key',
    });
    await expect(badSigner.sign()).rejects.toThrow(
      /Failed to import the Microsoft auth provider's certificate private key/,
    );
  });
});
