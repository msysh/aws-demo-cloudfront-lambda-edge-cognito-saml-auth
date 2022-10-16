export interface ContextParameter {
  readonly cognitoNamePrefix: string,
  readonly cognitoDomain: string,
  readonly cognitoCallbackUrl: string,
  readonly cognitoCallbackPath: string,
  readonly cognitoLogoutUrl: string,
  readonly cognitoSamlMetadataDocEndpoint: string,
}