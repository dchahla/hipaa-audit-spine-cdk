# HIPAA audit spine (AWS CDK)

An immutable audit and encryption core for a HIPAA-aligned architecture, in one AWS CDK stack: a rotating KMS customer-managed key, two WORM S3 buckets (Object Lock COMPLIANCE, encrypted under the CMK), deny-unencrypted and deny-non-TLS bucket policies, and a CloudTrail delivering management and S3 data events into the audit bucket. Each resource maps to a HIPAA §164.312 technical safeguard.

## What it creates

| Resource | §164.312 |
|---|---|
| KMS CMK, rotation on | (a)(2)(iv) encryption at rest |
| Records bucket, WORM + SSE-KMS | (c)(1) integrity |
| Audit bucket, WORM + SSE-KMS | (b) audit controls |
| deny-unencrypted + deny-non-TLS policies | (a)(2)(iv), (e) |
| CloudTrail into the audit bucket | (b) audit controls |

## Prerequisites

- Node 18 or newer
- AWS credentials configured (`aws configure`, SSO, or `CDK_DEFAULT_*`)
- The CDK Toolkit: `npm i -g aws-cdk`

## Run

```bash
npm install
npx cdk synth            # print the CloudFormation
npx cdk bootstrap        # first time per account/region
npx cdk deploy
```

## Configuration

All optional, via environment variables:

- `NAME_PREFIX`: prefix for resource names (default `audit-spine`)
- `RETENTION_YEARS`: Object Lock COMPLIANCE retention (default `7`)
- `CDK_DEFAULT_ACCOUNT` / `CDK_DEFAULT_REGION`: target account and region

## Heads up: COMPLIANCE Object Lock

The buckets use S3 Object Lock in COMPLIANCE mode. Once written, objects cannot be deleted or overwritten until retention expires, not even by the account root, and the bucket cannot be deleted while it holds locked objects. Do not point test or throwaway writes at a deployed records bucket.
