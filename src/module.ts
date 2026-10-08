import { createBackendModule } from '@backstage/backend-plugin-api';
import {
  authProvidersExtensionPoint,
  commonSignInResolvers,
  createOAuthProviderFactory,
} from '@backstage/plugin-auth-node';
import { microsoftCertificateAuthenticator } from './authenticator';
import { microsoftCertificateSignInResolvers } from './resolvers';

/**
 * Registers a `microsoft` auth provider that authenticates to Microsoft
 * Entra ID as a confidential client using a certificate-based client
 * assertion instead of a client secret.
 *
 * Do not install this alongside
 * `@backstage/plugin-auth-backend-module-microsoft-provider` - both modules
 * register the same `microsoft` provider id and will conflict.
 *
 * @public
 */
export const authModuleMicrosoftCertificateProvider = createBackendModule({
  pluginId: 'auth',
  moduleId: 'microsoft-certificate-provider',
  register(reg) {
    reg.registerInit({
      deps: {
        providers: authProvidersExtensionPoint,
      },
      async init({ providers }) {
        providers.registerProvider({
          providerId: 'microsoft',
          factory: createOAuthProviderFactory({
            authenticator: microsoftCertificateAuthenticator,
            signInResolverFactories: {
              ...microsoftCertificateSignInResolvers,
              ...commonSignInResolvers,
            },
          }),
        });
      },
    });
  },
});
