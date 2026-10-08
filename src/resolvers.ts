import {
  createSignInResolverFactory,
  OAuthAuthenticatorResult,
  PassportProfile,
  SignInInfo,
} from '@backstage/plugin-auth-node';
import { z } from 'zod/v3';

/**
 * Available sign-in resolvers for the Microsoft certificate auth provider.
 * Identical to the stock Microsoft provider's resolvers - the certificate
 * swap only changes how the backend authenticates to Entra ID, not the
 * shape of the resulting profile.
 *
 * @public
 */
export namespace microsoftCertificateSignInResolvers {
  export const emailMatchingUserEntityAnnotation = createSignInResolverFactory(
    {
      optionsSchema: z
        .object({
          dangerouslyAllowSignInWithoutUserInCatalog: z.boolean().optional(),
        })
        .optional(),
      create(options = {}) {
        return async (
          info: SignInInfo<OAuthAuthenticatorResult<PassportProfile>>,
          ctx,
        ) => {
          const { profile } = info;

          if (!profile.email) {
            throw new Error('Microsoft profile contained no email');
          }

          return ctx.signInWithCatalogUser(
            {
              annotations: {
                'microsoft.com/email': profile.email,
              },
            },
            {
              dangerousEntityRefFallback:
                options?.dangerouslyAllowSignInWithoutUserInCatalog
                  ? { entityRef: { name: profile.email } }
                  : undefined,
            },
          );
        };
      },
    },
  );

  export const userIdMatchingUserEntityAnnotation = createSignInResolverFactory(
    {
      optionsSchema: z
        .object({
          dangerouslyAllowSignInWithoutUserInCatalog: z.boolean().optional(),
        })
        .optional(),
      create(options = {}) {
        return async (
          info: SignInInfo<OAuthAuthenticatorResult<PassportProfile>>,
          ctx,
        ) => {
          const { result } = info;
          const id = result.fullProfile.id;

          if (!id) {
            throw new Error('Microsoft profile contained no id');
          }

          return ctx.signInWithCatalogUser(
            {
              annotations: {
                'graph.microsoft.com/user-id': id,
              },
            },
            {
              dangerousEntityRefFallback:
                options?.dangerouslyAllowSignInWithoutUserInCatalog
                  ? { entityRef: { name: id } }
                  : undefined,
            },
          );
        };
      },
    },
  );
}
