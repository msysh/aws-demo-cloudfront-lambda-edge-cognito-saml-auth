import {
  aws_cloudfront as cloudfront,
  aws_cloudfront_origins as origins,
  aws_lambda as lambda,
  CfnOutput,
} from 'aws-cdk-lib';
import { Construct } from 'constructs';

export interface CloudFrontProps {
  edgeLambdaVersion: lambda.Version
}

export class CloudFront {

  public readonly distributionDomainName: string;

  constructor(scope: Construct, props: CloudFrontProps){
    // -----------------------------
    // CloudFront
    // -----------------------------
    const distribution = new cloudfront.Distribution(scope, 'distribution', {
      defaultBehavior: {
        origin: new origins.HttpOrigin('aws.amazon.com'),
        edgeLambdas: [{
          eventType: cloudfront.LambdaEdgeEventType.VIEWER_REQUEST,
          functionVersion: props.edgeLambdaVersion,
          includeBody: false
        }],
        viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
      },
      defaultRootObject: 'index.html',
      enabled: true,
    });

    this.distributionDomainName = distribution.distributionDomainName;

    // -----------------------------
    // Output
    // -----------------------------
    new CfnOutput(scope, 'cloudfront-distribution-domain-name', {
      description: 'CloudFront distribution domain name',
      value: distribution.distributionDomainName
    });
  }
}