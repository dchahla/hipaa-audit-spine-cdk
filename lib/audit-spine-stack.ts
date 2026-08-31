import { Stack, StackProps, Duration, RemovalPolicy, CfnOutput, Tags } from 'aws-cdk-lib';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as cloudtrail from 'aws-cdk-lib/aws-cloudtrail';
import * as iam from 'aws-cdk-lib/aws-iam';
import { Construct } from 'constructs';

/**
 * Audit spine: the encryption and immutable-audit core of a HIPAA-aligned architecture.
 *
 * A KMS CMK, two WORM (Object Lock COMPLIANCE) buckets encrypted under it, deny-unencrypted and
 * deny-non-TLS bucket policies, and a CloudTrail delivering into the audit bucket. Each resource
 * maps to a HIPAA 164.312 technical safeguard: (a)(2)(iv) encryption at rest, (b) audit controls,
 * (c)(1) integrity, (e) transmission security.
 */
export interface AuditSpineProps extends StackProps {
  /** Prefix for all resource names. */
  readonly namePrefix?: string;
  /** WORM retention (Object Lock COMPLIANCE) in years, for both buckets. */
  readonly retentionYears?: number;
}

export class AuditSpineStack extends Stack {
  constructor(scope: Construct, id: string, props: AuditSpineProps = {}) {
    super(scope, id, props);

    const prefix = props.namePrefix ?? 'audit-spine';
    const years = props.retentionYears ?? 7;
    // S3 Object Lock accepts Years OR Days; CDK's L2 models retention as a Duration (days) and does
    // not expose Years. 365 * years is two days short of 7 calendar years once leap days land, so we
    // round up: Math.ceil(365.25 * 7) = 2557. A legal retention floor should never fall short.
    const retention = s3.ObjectLockRetention.compliance(Duration.days(Math.ceil(365.25 * years)));

    Tags.of(this).add('Project', prefix);

    // --- KMS CMK: the single key. Rotation on. 164.312(a)(2)(iv). --------------------------------
    const cmk = new kms.Key(this, 'Cmk', {
      alias: `${prefix}-cmk`,
      description: `${prefix} customer-managed key for ePHI encryption at rest`,
      enableKeyRotation: true,
      pendingWindow: Duration.days(7),
      removalPolicy: RemovalPolicy.DESTROY, // dev; real deploy would RETAIN
    });

    // CloudTrail encrypts its log files with this CMK, so its service principal must be allowed to
    // use the key. Without this, AWS rejects CreateTrail with InsufficientEncryptionPolicyException.
    cmk.grant(new iam.ServicePrincipal('cloudtrail.amazonaws.com'),
      'kms:GenerateDataKey*', 'kms:DescribeKey');

    // --- Records bucket: WORM store for signed records. 164.312(c)(1). ---------------------------
    const records = new s3.Bucket(this, 'Records', {
      bucketName: `${prefix}-records`,
      objectLockEnabled: true,
      objectLockDefaultRetention: retention,
      versioned: true, // Object Lock requires versioning
      encryption: s3.BucketEncryption.KMS,
      encryptionKey: cmk,
      bucketKeyEnabled: true,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true, // one line writes the deny-non-TLS bucket policy: 164.312(e)
      removalPolicy: RemovalPolicy.RETAIN, // WORM: never auto-delete
    });

    // deny-unencrypted put (the deny-non-TLS half is handled by enforceSSL above).
    records.addToResourcePolicy(new iam.PolicyStatement({
      sid: 'DenyUnencryptedPut',
      effect: iam.Effect.DENY,
      principals: [new iam.AnyPrincipal()],
      actions: ['s3:PutObject'],
      resources: [records.arnForObjects('*')],
      conditions: { StringNotEquals: { 's3:x-amz-server-side-encryption': 'aws:kms' } },
    }));

    // --- Audit-archive bucket: CloudTrail destination, WORM. 164.312(b). -------------------------
    const audit = new s3.Bucket(this, 'Audit', {
      bucketName: `${prefix}-audit-archive`,
      objectLockEnabled: true,
      objectLockDefaultRetention: retention,
      versioned: true,
      encryption: s3.BucketEncryption.KMS,
      encryptionKey: cmk,
      bucketKeyEnabled: true,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      removalPolicy: RemovalPolicy.RETAIN,
    });

    // --- CloudTrail -> audit bucket, management + S3 data events on records. 164.312(b). ---------
    // Passing the audit bucket to the trail makes CDK add the required CloudTrail bucket policy
    // (AclCheck + Write) automatically.
    const trail = new cloudtrail.Trail(this, 'Trail', {
      trailName: `${prefix}-trail`,
      bucket: audit,
      encryptionKey: cmk,
      includeGlobalServiceEvents: true,
      isMultiRegionTrail: true,
      enableFileValidation: true,
    });
    trail.addS3EventSelector([{ bucket: records }], {
      readWriteType: cloudtrail.ReadWriteType.ALL,
      includeManagementEvents: true,
    });

    new CfnOutput(this, 'CmkArn', { value: cmk.keyArn });
    new CfnOutput(this, 'RecordsBucket', { value: records.bucketName });
    new CfnOutput(this, 'AuditBucket', { value: audit.bucketName });
    new CfnOutput(this, 'TrailArn', { value: trail.trailArn });
  }
}
