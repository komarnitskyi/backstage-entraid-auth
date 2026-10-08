import {
  createOAuthAuthenticator,
  OAuthAuthenticatorResult,
  PassportOAuthAuthenticatorHelper,
  PassportProfile,
} from '@backstage/plugin-auth-node';
import {
  fetchGraphProfile,
  GRAPH_PROFILE_SCOPE,
  isGraphScopedToken,
} from './graphProfile';
import { MicrosoftTokenClient, MicrosoftTokenResponse } from './tokenClient';

interface AuthenticatorContext {
  tokenClient: MicrosoftTokenClient;
  callbackUrl: string;
  skipUserProfile: boolean;
  domainHint?: string;
}

/**
 * Resolves the user's profile for a token response. When the access token
 * isn't scoped to call Microsoft Graph (e.g. the user only requested a
 * downstream API's resource scope), a separate Graph-scoped token is
 * requested from the stored refresh token purely to fetch the profile - the
 * session keeps the originally issued access token untouched.
 */
async function resolveProfile(
  tokenResponse: MicrosoftTokenResponse,
  ctx: AuthenticatorContext,
): Promise<PassportProfile> {
  if (ctx.skipUserProfile) {
    return { provider: 'microsoft', id: '', displayName: '' };
  }

  if (isGraphScopedToken(tokenResponse.access_token)) {
    return fetchGraphProfile(tokenResponse.access_token);
  }

  if (!tokenResponse.refresh_token) {
    return { provider: 'microsoft', id: '', displayName: '' };
  }

  const graphTokens = await ctx.tokenClient.exchangeRefreshToken(
    tokenResponse.refresh_token,
    GRAPH_PROFILE_SCOPE,
  );
  return fetchGraphProfile(graphTokens.access_token);
}

async function buildResult(
  tokenResponse: MicrosoftTokenResponse,
  ctx: AuthenticatorContext,
): Promise<OAuthAuthenticatorResult<PassportProfile>> {
  const fullProfile = await resolveProfile(tokenResponse, ctx);

  return {
    fullProfile,
    session: {
      accessToken: tokenResponse.access_token,
      tokenType: tokenResponse.token_type ?? 'bearer',
      scope: tokenResponse.scope ?? '',
      expiresInSeconds: tokenResponse.expires_in,
      idToken: tokenResponse.id_token,
      refreshToken: tokenResponse.refresh_token,
    },
  };
}

/**
 * A Microsoft/Entra ID OAuth authenticator that authenticates to the token
 * endpoint as a confidential client using a certificate-based JWT assertion
 * (`private_key_jwt`), instead of a `client_secret`.
 *
 * @public
 */
export const microsoftCertificateAuthenticator = createOAuthAuthenticator({
  defaultProfileTransform:
    PassportOAuthAuthenticatorHelper.defaultProfileTransform,
  scopes: {
    required: ['email', 'openid', 'offline_access', 'user.read'],
    transform({ requested, granted, required, additional }) {
      const hasResourceScope = Array.from(requested).some(s =>
        s.includes('/'),
      );
      if (hasResourceScope) {
        return [...requested, 'offline_access'];
      }
      return [...requested, ...granted, ...required, ...additional];
    },
  },

  initialize({ callbackUrl, config }) {
    const clientId = config.getString('clientId');
    const tenantId = config.getString('tenantId');
    const privateKeyPem = config.getString('certificate.privateKey');
    const certificatePem = config.getString('certificate.certificate');
    const skipUserProfile =
      config.getOptionalBoolean('skipUserProfile') ?? false;
    const domainHint = config.getOptionalString('domainHint');

    const tokenClient = new MicrosoftTokenClient({
      clientId,
      tenantId,
      privateKeyPem,
      certificatePem,
    });

    return { tokenClient, callbackUrl, skipUserProfile, domainHint };
  },

  async start(input, ctx) {
    const url = new URL(ctx.tokenClient.authorizeEndpoint);
    url.searchParams.set('client_id', ctx.tokenClient.clientId);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('response_mode', 'query');
    url.searchParams.set('redirect_uri', ctx.callbackUrl);
    url.searchParams.set('scope', input.scope);
    url.searchParams.set('state', input.state);
    if (ctx.domainHint !== undefined) {
      url.searchParams.set('domain_hint', ctx.domainHint);
    }
    return { url: url.toString() };
  },

  async authenticate(input, ctx) {
    const { req } = input;
    const code = req.query.code;

    if (typeof code !== 'string') {
      const error =
        typeof req.query.error === 'string' ? req.query.error : 'access_denied';
      const errorDescription =
        typeof req.query.error_description === 'string'
          ? req.query.error_description
          : undefined;
      throw new Error(
        `Microsoft authorization failed: ${error}${
          errorDescription ? ` - ${errorDescription}` : ''
        }`,
      );
    }

    const tokenResponse = await ctx.tokenClient.exchangeAuthorizationCode(
      code,
      ctx.callbackUrl,
    );
    return buildResult(tokenResponse, ctx);
  },

  async refresh(input, ctx) {
    const tokenResponse = await ctx.tokenClient.exchangeRefreshToken(
      input.refreshToken,
      input.scope,
    );
    return buildResult(tokenResponse, ctx);
  },
});
