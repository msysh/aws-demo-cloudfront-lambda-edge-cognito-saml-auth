#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { CloudfrontLambdaEdgeStack } from '../lib/cloudfront-lambda-edge-stack';
import { CognitoSamlAuthStack } from '../lib/cognito-saml-auth-stack';

const app = new cdk.App();

new CognitoSamlAuthStack(app, 'CognitoSamlAuthStack', {});

new CloudfrontLambdaEdgeStack(app, 'CloudfrontLambdaEdgeStack', {});
