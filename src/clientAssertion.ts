import { createHash, randomUUID } from 'crypto';
import { importPKCS8, SignJWT, type KeyLike } from 'jose';

/** @public */
export interface CertificateCredentialConfig {
  clientId: string;
  tokenEndpoint: string;
  /** PEM-encoded PKCS8 private key, without a passphrase. */
  privateKeyPem: string;
  /** PEM-encoded X.509 certificate matching the private key. */
  certificatePem: string;
}

/**
 * Computes the base64url-encoded SHA-1 thumbprint of an X.509 certificate,
 * as required in the `x5t` header of a Microsoft Entra ID client assertion.
 */
export function certificateThumbprint(certificatePem: string): string {
  if (
    !certificatePem.includes('-----BEGIN CERTIFICATE-----') ||
    !certificatePem.includes('-----END CERTIFICATE-----')
  ) {
    throw new Error(
      'Invalid certificate: expected a PEM-encoded X.509 certificate (-----BEGIN CERTIFICATE-----)',
    );
  }

  const base64Body = certificatePem
    .replace(/-----BEGIN CERTIFICATE-----/g, '')
    .replace(/-----END CERTIFICATE-----/g, '')
    .replace(/\s+/g, '');

  const der = Buffer.from(base64Body, 'base64');
  return createHash('sha1').update(der).digest('base64url');
}

/**
 * Builds the signed JWT client assertion that Microsoft Entra ID accepts in
 * place of a `client_secret` for confidential client authentication
 * (`private_key_jwt`, RFC 7523 / OAuth 2.0 JWT Bearer assertion).
 *
 * @public
 */
export class ClientAssertionSigner {
  private readonly thumbprint: string;
  private key: Promise<KeyLike> | undefined;

  constructor(private readonly config: CertificateCredentialConfig) {
    this.thumbprint = certificateThumbprint(config.certificatePem);
  }

  private getKey(): Promise<KeyLike> {
    if (!this.key) {
      this.key = importPKCS8(this.config.privateKeyPem, 'RS256').catch(
        err => {
          this.key = undefined;
          throw new Error(
            `Failed to import the Microsoft auth provider's certificate private key. It must be an unencrypted PKCS8 PEM (e.g. "openssl pkcs8 -topk8 -nocrypt"). Cause: ${err.message}`,
          );
        },
      );
    }
    return this.key;
  }

  async sign(): Promise<string> {
    const key = await this.getKey();
    const now = Math.floor(Date.now() / 1000);

    return new SignJWT({})
      .setProtectedHeader({
        alg: 'RS256',
        typ: 'JWT',
        x5t: this.thumbprint,
      })
      .setIssuer(this.config.clientId)
      .setSubject(this.config.clientId)
      .setAudience(this.config.tokenEndpoint)
      .setJti(randomUUID())
      .setIssuedAt(now)
      .setNotBefore(now)
      .setExpirationTime(now + 5 * 60)
      .sign(key);
  }
}
