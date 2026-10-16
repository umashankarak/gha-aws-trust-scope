const provider = new aws.iam.OpenIdConnectProvider("p", {
  url: 'https://token.actions.githubusercontent.com',
  clientIdLists: ['sts.amazonaws.com'],
});
const role = new aws.iam.Role("r", {
  assumeRolePolicy: JSON.stringify({
    Version: '2012-10-17',
    Statement: [{
      Effect: 'Allow',
      Principal: { Federated: arn },
      Action: 'sts:AssumeRoleWithWebIdentity',
      Condition: { StringEquals: { 'token.actions.githubusercontent.com:aud': 'sts.amazonaws.com' } },
    }],
  }),
});
