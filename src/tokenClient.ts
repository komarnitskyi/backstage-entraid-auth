import { ClientAssertionSigner } from './clientAssertion';

const CLIENT_ASSERTION_TYPE =
  'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

/** @public */
export interface MicrosoftTokenResponse {
  access_token: string;
  refresh_token?: string;
  id_token?: string;
  token_type: string;
  expires_in: number;
  scope?: string;
}

/** @public */
export interface MicrosoftTokenClientConfig {
  clientId: string;
  tenantId: string;
  certificatePem: string;
  privateKeyPem: string;
}

/**
 * Talks to the Microsoft identity platform's v2.0 authorize/token endpoints
 * directly, authenticating as a confidential client with a certificate-based
 * JWT assertion instead of a client secret.
 *
 * @public
 */
export class MicrosoftTokenClient {
  readonly clientId: string;
  readonly authorizeEndpoint: string;
  readonly tokenEndpoint: string;
  private readonly assertionSigner: ClientAssertionSigner;

  constructor(config: MicrosoftTokenClientConfig) {
    this.clientId = config.clientId;
    this.authorizeEndpoint = `https://login.microsoftonline.com/${config.tenantId}/oauth2/v2.0/authorize`;
    this.tokenEndpoint = `https://login.microsoftonline.com/${config.tenantId}/oauth2/v2.0/token`;
    this.assertionSigner = new ClientAssertionSigner({
      clientId: config.clientId,
      tokenEndpoint: this.tokenEndpoint,
      certificatePem: config.certificatePem,
      privateKeyPem: config.privateKeyPem,
    });
  }

  async exchangeAuthorizationCode(
    code: string,
    redirectUri: string,
  ): Promise<MicrosoftTokenResponse> {
    return this.request({
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirectUri,
    });
  }

  async exchangeRefreshToken(
    refreshToken: string,
    scope: string,
  ): Promise<MicrosoftTokenResponse> {
    return this.request({
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      scope,
    });
  }

  private async request(
    params: Record<string, string>,
  ): Promise<MicrosoftTokenResponse> {
    const assertion = await this.assertionSigner.sign();

    const body = new URLSearchParams({
      ...params,
      client_id: this.clientId,
      client_assertion_type: CLIENT_ASSERTION_TYPE,
      client_assertion: assertion,
    });

    const response = await fetch(this.tokenEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    });

    const text = await response.text();
    let payload: any;
    try {
      payload = text ? JSON.parse(text) : {};
    } catch {
      payload = { error: 'invalid_response', error_description: text };
    }

    if (!response.ok) {
      const description =
        payload.error_description ?? payload.error ?? response.statusText;
      throw new Error(
        `Microsoft identity platform token request failed (${response.status}): ${description}`,
      );
    }

    return payload as MicrosoftTokenResponse;
  }
}
