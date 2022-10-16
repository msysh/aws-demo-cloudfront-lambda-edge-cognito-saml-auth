import {
  aws_cognito as cognito,
  CfnOutput,
  Duration,
  RemovalPolicy,
} from 'aws-cdk-lib';
import { Construct } from 'constructs';

export interface CognitoProps {
  namePrefix: string,
  domain: string,
  samlMetadataDocEndpoint: string,
  callbackUrl: string,
  logoutUrl: string,
}

export class Cognito {

  constructor (scope: Construct, props: CognitoProps){

    // -----------------------------
    // Cognito UserPool
    // -----------------------------
    const userPool = new cognito.UserPool(scope, 'cognito-user-pool', {
      userPoolName: `${props.namePrefix}-user-pool`,
      accountRecovery: cognito.AccountRecovery.NONE,
      autoVerify: {
        email: true,
        phone: false
      },
      enableSmsRole: false,
      passwordPolicy: {
        minLength: 8,
        requireDigits: true,
        requireLowercase: true,
        requireSymbols: true,
        requireUppercase: true,
        tempPasswordValidity: Duration.days(7)
      },
      removalPolicy: RemovalPolicy.DESTROY,
      selfSignUpEnabled: false,
      signInAliases: {
        email: true,
      },
      signInCaseSensitive: false,
      standardAttributes: {
        email: { mutable: true, required: true }
      }
    });

    // -----------------------------
    // User Pool Identity Provider
    // -----------------------------
    const userPoolProvider = new cognito.UserPoolIdentityProviderSaml(scope, 'cognito-user-pool-identity-provider', {
      name: `${props.namePrefix}-idp`,
      metadata: cognito.UserPoolIdentityProviderSamlMetadata.url(props.samlMetadataDocEndpoint),
      userPool: userPool,
      attributeMapping: {
        email: cognito.ProviderAttribute.other('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress')
      },
      idpSignout: true
    });

    // -----------------------------
    // Cognito App Client
    // -----------------------------
    const appClient = new cognito.UserPoolClient(scope, 'cognito-app-client', {
      userPool: userPool,
      userPoolClientName: `${props.namePrefix}-client-app`,
      authFlows: {
        adminUserPassword: false,
        custom: false,
        userPassword: false,
        userSrp: false
      },
      generateSecret: false,
      preventUserExistenceErrors: true,
      supportedIdentityProviders: [
        cognito.UserPoolClientIdentityProvider.custom(userPoolProvider.providerName)
      ],
      oAuth: {
        callbackUrls: [
          props.callbackUrl
        ],
        flows: {
          authorizationCodeGrant: true,
          implicitCodeGrant: false,
          clientCredentials: false
        },
        logoutUrls: [
          props.logoutUrl
        ],
        scopes: [
          cognito.OAuthScope.OPENID,
          cognito.OAuthScope.EMAIL
        ],
      },
    });

    const domain = userPool.addDomain('cognito-domain', {
      cognitoDomain: {
        domainPrefix: props.domain
      }
    });

    // -----------------------------
    // Output
    // -----------------------------
    new CfnOutput(scope, 'output-user-pool-id', {
      description: 'Cognito User Pool ID',
      value: userPool.userPoolId,
    });

    new CfnOutput(scope, 'output-user-pool-id-provider', {
      description: 'Cognito User Pool ID Provider Name',
      value: userPoolProvider.providerName,
    });

    new CfnOutput(scope, 'output-app-client-id', {
      description: 'Cognito App Client ID',
      value: appClient.userPoolClientId,
    });

    new CfnOutput(scope, 'output-domain-prefix', {
      description: 'Cognito Domain Prefix',
      value: props.domain,
    });
  }
}