const oidcProviderUrl = "token.actions.githubusercontent.com";
const existingOidcArn = `arn:aws:iam::210987654321:oidc-provider/token.actions.githubusercontent.com`;
const oidcConditions = [
  { test: "StringEquals", variable: `${oidcProviderUrl}:aud`, values: ["sts.amazonaws.com"] },
  { test: "StringLike",  variable: `${oidcProviderUrl}:sub`, values: [`repo:acme/web:*`] },
];
const secretsRole = new aws.iam.Role("r", {
  assumeRolePolicy: aws.iam.getPolicyDocumentOutput({
    statements: [{
      effect: "Allow",
      principals: [{ type: "Federated", identifiers: [oidcProviderArn] }],
      actions: ["sts:AssumeRoleWithWebIdentity"],
      conditions: oidcConditions,
    }],
  }).json,
});
