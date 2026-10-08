import { HumanDuration } from '@backstage/types';

export interface Config {
  auth?: {
    providers?: {
      /** @visibility frontend */
      microsoft?: {
        [authEnv: string]: {
          clientId: string;
          tenantId: string;
          /**
           * Certificate-based credential for authenticating as a
           * confidential client (`private_key_jwt`), used instead of
           * `clientSecret`.
           */
          certificate: {
            /**
             * PEM-encoded X.509 certificate uploaded to the app
             * registration's "Certificates & secrets" blade. Only the
             * public certificate - never the private key - is uploaded to
             * Entra ID.
             * @visibility secret
             */
            certificate: string;
            /**
             * PEM-encoded PKCS8 private key matching `certificate`, without
             * a passphrase (convert with
             * `openssl pkcs8 -topk8 -nocrypt -in key.pem -out key.pkcs8.pem`
             * if needed).
             * @visibility secret
             */
            privateKey: string;
          };
          domainHint?: string;
          callbackUrl?: string;
          additionalScopes?: string | string[];
          skipUserProfile?: boolean;
          sessionDuration?: HumanDuration | string;
          signIn?: {
            resolvers: Array<
              | {
                  resolver: 'emailMatchingUserEntityAnnotation';
                  dangerouslyAllowSignInWithoutUserInCatalog?: boolean;
                }
              | {
                  resolver: 'emailLocalPartMatchingUserEntityName';
                  allowedDomains?: string[];
                  dangerouslyAllowSignInWithoutUserInCatalog?: boolean;
                }
              | {
                  resolver: 'emailMatchingUserEntityProfileEmail';
                  dangerouslyAllowSignInWithoutUserInCatalog?: boolean;
                }
              | {
                  resolver: 'userIdMatchingUserEntityAnnotation';
                  dangerouslyAllowSignInWithoutUserInCatalog?: boolean;
                }
            >;
          };
        };
      };
    };
  };
}
