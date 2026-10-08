import { decodeJwt } from 'jose';
import type { PassportProfile } from '@backstage/plugin-auth-node';

const GRAPH_BASE_URL = 'https://graph.microsoft.com/v1.0';
const GRAPH_AUDIENCE = '00000003-0000-0000-c000-000000000000';

/**
 * The scope used to fetch a Graph-scoped token purely for profile lookup,
 * when the session's main access token targets a different resource.
 *
 * @public
 */
export const GRAPH_PROFILE_SCOPE = 'openid email User.Read offline_access';

/**
 * Whether an access token is already scoped to call the Microsoft Graph
 * `/me` endpoint, i.e. it targets the Graph audience and carries a
 * `User.Read`-equivalent scope.
 *
 * @public
 */
export function isGraphScopedToken(accessToken: string): boolean {
  try {
    const { aud, scp } = decodeJwt(accessToken) as {
      aud?: string;
      scp?: string;
    };
    if (aud !== GRAPH_AUDIENCE || !scp) {
      return false;
    }
    return scp
      .split(' ')
      .map(s => s.toLowerCase())
      .some(s => ['user.read', 'user.read.all'].includes(s));
  } catch {
    return false;
  }
}

/**
 * Fetches and normalizes the signed-in user's profile from Microsoft Graph,
 * in the same shape `passport-microsoft` produces, so it stays compatible
 * with the stock sign-in resolvers and profile transforms.
 *
 * @public
 */
export async function fetchGraphProfile(
  accessToken: string,
): Promise<PassportProfile> {
  const response = await fetch(`${GRAPH_BASE_URL}/me`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });

  if (!response.ok) {
    throw new Error(
      `Failed to fetch Microsoft Graph profile (${response.status}): ${response.statusText}`,
    );
  }

  const json = (await response.json()) as {
    id?: string;
    displayName?: string;
    surname?: string;
    givenName?: string;
    mail?: string;
  };

  const profile: PassportProfile = {
    provider: 'microsoft',
    id: json.id ?? '',
    displayName: json.displayName ?? '',
    name: {
      familyName: json.surname ?? '',
      givenName: json.givenName ?? '',
    },
    emails:
      typeof json.mail === 'string' && json.mail.trim()
        ? [{ value: json.mail }]
        : [],
  };

  const photo = await fetchProfilePhoto(accessToken);
  if (photo) {
    profile.photos = [{ value: photo }];
  }

  return profile;
}

async function fetchProfilePhoto(
  accessToken: string,
): Promise<string | undefined> {
  try {
    const response = await fetch(`${GRAPH_BASE_URL}/me/photos/96x96/$value`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    if (!response.ok) {
      return undefined;
    }
    const data = await response.arrayBuffer();
    return `data:image/jpeg;base64,${Buffer.from(data).toString('base64')}`;
  } catch {
    return undefined;
  }
}
