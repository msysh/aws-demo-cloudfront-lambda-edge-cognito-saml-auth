import {
  aws_iam as iam,
  aws_lambda as lambda,
  CfnOutput,
  AssetHashType,
  Duration,
} from 'aws-cdk-lib';
import { Construct } from 'constructs';

export interface LambdaEdgeProps {
}

export class LambdaEdge {

  public readonly lambdaVersion: lambda.Version;

  constructor(scope: Construct, props?: LambdaEdgeProps){

    // -----------------------------
    // IAM
    // -----------------------------
    const role = new iam.Role(scope, 'role', {
      assumedBy: new iam.CompositePrincipal(
        new iam.ServicePrincipal('lambda.amazonaws.com'),
        new iam.ServicePrincipal('edgelambda.amazonaws.com')
      ),
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AWSLambdaBasicExecutionRole'),
      ],
    });

    // -----------------------------
    // Lambda
    // -----------------------------
    const lambdaFunction = new lambda.Function(scope, 'function', {
      architecture: lambda.Architecture.X86_64,
      runtime: lambda.Runtime.PYTHON_3_9,
      handler: 'app.lambda_handler',
      memorySize: 128,
      timeout: Duration.seconds(5),
      role: role,
      environment: {
        // Environment values cannot be used at LambdaEdge
      },
      // code: lambda.AssetCode.fromAsset('assets/lambda-edge'),
      code: lambda.AssetCode.fromAsset('assets/lambda-edge', {
        assetHashType: AssetHashType.OUTPUT,
        bundling: {
          image: lambda.Runtime.PYTHON_3_9.bundlingImage,
          command: [
            'bash',
            '-c',
            [
              'cp -r ./* /asset-output',
              'pip install -t /asset-output --requirement requirements.txt',
            ].join(' && ')
          ],
          user: 'root',
        }
      }),
    });

    this.lambdaVersion = lambdaFunction.currentVersion;

    // -----------------------------
    // Output
    // -----------------------------
    new CfnOutput(scope, 'lambda-attached-role', {
      description: 'IAM Role attached lambda',
      value: role.roleName
    });

    new CfnOutput(scope, 'lambda-function-name', {
      description: 'Lambda function name',
      value: lambdaFunction.functionName
    });

    new CfnOutput(scope, 'lambda-function-version', {
      description: 'Lambda function version',
      value: lambdaFunction.currentVersion.version
    });
  }
}