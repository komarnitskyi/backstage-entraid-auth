/**
 * A Backstage auth backend module providing a Microsoft/Entra ID OAuth
 * provider that authenticates with a certificate instead of a client secret.
 *
 * @packageDocumentation
 */

export { microsoftCertificateAuthenticator } from './authenticator';
export { authModuleMicrosoftCertificateProvider as default } from './module';
export { microsoftCertificateSignInResolvers } from './resolvers';
export { certificateThumbprint, ClientAssertionSigner } from './clientAssertion';
export { MicrosoftTokenClient } from './tokenClient';
export type {
  CertificateCredentialConfig,
} from './clientAssertion';
export type {
  MicrosoftTokenClientConfig,
  MicrosoftTokenResponse,
} from './tokenClient';
