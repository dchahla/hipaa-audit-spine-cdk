#!/usr/bin/env node
import { App, Environment } from 'aws-cdk-lib';
import { AuditSpineStack } from '../lib/audit-spine-stack';

const app = new App();

// Account and region come from your AWS environment (CDK_DEFAULT_* or the active profile).
const env: Environment = {
  account: process.env.CDK_DEFAULT_ACCOUNT,
  region: process.env.CDK_DEFAULT_REGION ?? 'us-east-1',
};

new AuditSpineStack(app, 'AuditSpine', {
  env,
  namePrefix: process.env.NAME_PREFIX ?? 'audit-spine',
  retentionYears: Number(process.env.RETENTION_YEARS ?? 7),
});
