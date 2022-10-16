import {
  Stack,
  StackProps,
  Tags
} from 'aws-cdk-lib';
import { Construct } from 'constructs';

import { ContextParameter } from './context-parameter';
import { Cognito } from './cognito';

export class CognitoSamlAuthStack extends Stack {

  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    const contextParam: ContextParameter = this.node.tryGetContext('cloudfront-lambdaedge-cognito-saml-auth') as ContextParameter;

    if (!contextParam) {
      throw new Error('You need to configure context parameters. "cloudfront-lambdaedge-cognito-saml-auth".("cognitoNamePrefix", "cognitoDmain", "cognitoCallbackUrl", "cognitoCallbackPath", "cognitoSamlMetadataDocEndpoint")');
    }

    const COGNITO_NAME_PREFIX = contextParam?.cognitoNamePrefix || 'my-organization-sso';
    const DOMAIN = contextParam?.cognitoDomain || 'my-organization';
    const CALLBACK_URL = `${contextParam?.cognitoCallbackUrl}${contextParam?.cognitoCallbackPath}` || 'https://xxxxx.cloudfront.net';
    const LOGOUT_URL = contextParam?.cognitoLogoutUrl || CALLBACK_URL;
    const SAML_METADATA_DOC_ENDPOINT = contextParam?.cognitoSamlMetadataDocEndpoint || 'https://portal.sso.us-east-1.amazonaws.com/saml/metadata/XXXXXXXXXXXXXXXXXXXXXX';

    const cognito = new Cognito(this, {
      namePrefix: COGNITO_NAME_PREFIX,
      domain: DOMAIN,
      samlMetadataDocEndpoint: SAML_METADATA_DOC_ENDPOINT,
      callbackUrl: CALLBACK_URL,
      logoutUrl: LOGOUT_URL,
    });
  }
}
