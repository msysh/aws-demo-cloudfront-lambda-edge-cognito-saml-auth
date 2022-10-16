import {
  Stack,
  StackProps,
  Tags
} from 'aws-cdk-lib';
import { Construct } from 'constructs';

import { LambdaEdge } from './lambda-edge';
import { CloudFront } from './cloudfront';

export class CloudfrontLambdaEdgeStack extends Stack {

  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    const lambdaEdge: LambdaEdge = new LambdaEdge(this);

    new CloudFront(this, {
      edgeLambdaVersion: lambdaEdge.lambdaVersion
    });
  }
}