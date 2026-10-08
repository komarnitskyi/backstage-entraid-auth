import { readFileSync } from 'fs';
import { join } from 'path';
import { MicrosoftTokenClient } from '../tokenClient';

const CERT_PEM = readFileSync(
  join(__dirname, 'fixtures/test-cert.pem'),
  'utf8',
);
const KEY_PEM = readFileSync(
  join(__dirname, 'fixtures/test-key-pkcs8.pem'),
  'utf8',
);

describe('MicrosoftTokenClient', () => {
  const client = new MicrosoftTokenClient({
    clientId: 'test-client-id',
    tenantId: 'test-tenant-id',
    certificatePem: CERT_PEM,
    privateKeyPem: KEY_PEM,
  });

  const fetchMock = jest.fn();
  const originalFetch = global.fetch;

  beforeEach(() => {
    fetchMock.mockReset();
    global.fetch = fetchMock as any;
  });

  afterAll(() => {
    global.fetch = originalFetch;
  });

  it('builds the authorize/token endpoints from the tenant id', () => {
    expect(client.authorizeEndpoint).toBe(
      'https://login.microsoftonline.com/test-tenant-id/oauth2/v2.0/authorize',
    );
    expect(client.tokenEndpoint).toBe(
      'https://login.microsoftonline.com/test-tenant-id/oauth2/v2.0/token',
    );
  });

  it('sends a client_assertion instead of a client_secret on the authorization_code grant', async () => {
    fetchMock.mockResolvedValue({
      ok: true,
      text: async () =>
        JSON.stringify({
          access_token: 'at',
          refresh_token: 'rt',
          id_token: 'idt',
          token_type: 'Bearer',
          expires_in: 3600,
          scope: 'openid email',
        }),
    });

    const result = await client.exchangeAuthorizationCode(
      'auth-code',
      'https://backstage.example.com/api/auth/microsoft/handler/frame',
    );

    expect(result.access_token).toBe('at');
    expect(result.refresh_token).toBe('rt');

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe(client.tokenEndpoint);

    const body = new URLSearchParams(init.body);
    expect(body.get('grant_type')).toBe('authorization_code');
    expect(body.get('code')).toBe('auth-code');
    expect(body.get('redirect_uri')).toBe(
      'https://backstage.example.com/api/auth/microsoft/handler/frame',
    );
    expect(body.get('client_id')).toBe('test-client-id');
    expect(body.get('client_secret')).toBeNull();
    expect(body.get('client_assertion_type')).toBe(
      'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
    );
    expect(body.get('client_assertion')?.split('.')).toHaveLength(3);
  });

  it('sends the scope on the refresh_token grant', async () => {
    fetchMock.mockResolvedValue({
      ok: true,
      text: async () =>
        JSON.stringify({
          access_token: 'at2',
          token_type: 'Bearer',
          expires_in: 3600,
        }),
    });

    await client.exchangeRefreshToken('refresh-token', 'openid email');

    const [, init] = fetchMock.mock.calls[0];
    const body = new URLSearchParams(init.body);
    expect(body.get('grant_type')).toBe('refresh_token');
    expect(body.get('refresh_token')).toBe('refresh-token');
    expect(body.get('scope')).toBe('openid email');
  });

  it('throws a descriptive error when the token endpoint rejects the request', async () => {
    fetchMock.mockResolvedValue({
      ok: false,
      status: 401,
      statusText: 'Unauthorized',
      text: async () =>
        JSON.stringify({
          error: 'invalid_client',
          error_description: 'AADSTS700027: Client assertion failed signature validation.',
        }),
    });

    await expect(
      client.exchangeAuthorizationCode('bad-code', 'https://example.com'),
    ).rejects.toThrow(/AADSTS700027/);
  });
});
