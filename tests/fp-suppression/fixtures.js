/**
 * Synthetic scan fixtures for the false-positive suppression acceptance
 * test. Each resource carries an explicit ground-truth label:
 *   - true_positive: a real security issue that must never be hidden
 *   - false_positive: a known/accepted alert that suppression should remove
 *
 * The fixtures exercise three real, unmodified production plugins:
 * openSSH (EC2), ebsEncryptionEnabled (EC2) and bucketEncryption (S3).
 */

var ACCOUNT = '111122223333';
var REGION = 'us-east-1';

function sgArn(groupId) {
    return 'arn:aws:ec2:' + REGION + ':' + ACCOUNT + ':security-group/' + groupId;
}

function volArn(volumeId) {
    return 'arn:aws:ec2:' + REGION + ':' + ACCOUNT + ':volume/' + volumeId;
}

function bucketArn(name) {
    return 'arn:aws:s3:::' + name;
}

var securityGroups = [
    // False positive: penetration-testing jump box, tag-acknowledged.
    {
        GroupId: 'sg-fp-001',
        GroupName: 'pentest-jumpbox',
        OwnerId: ACCOUNT,
        Tags: [
            {Key: 'fp-acknowledged', Value: 'true'},
            {Key: 'reason', Value: 'authorized-pentest'}
        ],
        IpPermissions: [
            {
                IpProtocol: 'tcp',
                FromPort: 22,
                ToPort: 22,
                IpRanges: [{CidrIp: '0.0.0.0/0'}],
                Ipv6Ranges: [],
                UserIdGroupPairs: []
            }
        ],
        IpPermissionsEgress: []
    },
    // False positive: temporary migration SG, time-boxed via tags/window.
    {
        GroupId: 'sg-fp-002',
        GroupName: 'migration-temp',
        OwnerId: ACCOUNT,
        Tags: [
            {Key: 'environment', Value: 'temp-migration'}
        ],
        IpPermissions: [
            {
                IpProtocol: 'tcp',
                FromPort: 22,
                ToPort: 22,
                IpRanges: [{CidrIp: '0.0.0.0/0'}],
                Ipv6Ranges: [],
                UserIdGroupPairs: []
            }
        ],
        IpPermissionsEgress: []
    },
    // True positive: production SG with SSH open to the world, no ack tags.
    {
        GroupId: 'sg-tp-001',
        GroupName: 'production-web',
        OwnerId: ACCOUNT,
        Tags: [{Key: 'environment', Value: 'prod'}],
        IpPermissions: [
            {
                IpProtocol: 'tcp',
                FromPort: 22,
                ToPort: 22,
                IpRanges: [{CidrIp: '0.0.0.0/0'}],
                Ipv6Ranges: [],
                UserIdGroupPairs: []
            }
        ],
        IpPermissionsEgress: []
    },
    // Passing SG: no open SSH.
    {
        GroupId: 'sg-ok-001',
        GroupName: 'locked-down',
        OwnerId: ACCOUNT,
        Tags: [],
        IpPermissions: [
            {
                IpProtocol: 'tcp',
                FromPort: 443,
                ToPort: 443,
                IpRanges: [{CidrIp: '10.0.0.0/8'}],
                Ipv6Ranges: [],
                UserIdGroupPairs: []
            }
        ],
        IpPermissionsEgress: []
    }
];

var volumes = [
    // False positive: ephemeral test volume, encryption exception approved.
    {
        VolumeId: 'vol-fp-001',
        Encrypted: false,
        VolumeType: 'gp2',
        Tags: [
            {Key: 'exception-approved', Value: 'ephemeral-testing'}
        ]
    },
    // True positive: unencrypted production data volume.
    {
        VolumeId: 'vol-tp-001',
        Encrypted: false,
        VolumeType: 'gp2',
        Tags: [{Key: 'environment', Value: 'prod'}]
    },
    // Passing volume: encrypted.
    {
        VolumeId: 'vol-ok-001',
        Encrypted: true,
        KmsKeyId: 'arn:aws:kms:' + REGION + ':' + ACCOUNT + ':key/key-ok',
        VolumeType: 'gp2',
        Tags: []
    }
];

var kmsKey = {
    KeyMetadata: {
        KeyId: 'key-ok',
        Arn: 'arn:aws:kms:' + REGION + ':' + ACCOUNT + ':key/key-ok',
        Origin: 'AWS_KMS',
        KeyManager: 'AWS'
    }
};

var buckets = [
    // False positive: public logging bucket with an accepted encryption
    // exception for a migration window.
    {Name: 'fp-bucket-001'},
    // True positive: production bucket missing encryption.
    {Name: 'tp-bucket-001'},
    // Passing bucket: AES256 encryption configured.
    {Name: 'ok-bucket-001'}
];

function bucketTagging(name) {
    if (name === 'fp-bucket-001') {
        return {data: {TagSet: [{Key: 'exception-approved', Value: 'migration'}]}};
    }
    if (name === 'tp-bucket-001') {
        return {data: {TagSet: [{Key: 'environment', Value: 'prod'}]}};
    }
    return {data: {TagSet: [{Key: 'environment', Value: 'prod'}]}};
}

function bucketEncryptionEntry(name) {
    if (name === 'ok-bucket-001') {
        return {
            data: {
                ServerSideEncryptionConfiguration: {
                    Rules: [
                        {ApplyServerSideEncryptionByDefault: {SSEAlgorithm: 'AES256'}}
                    ]
                }
            }
        };
    }
    return {
        err: {
            message: 'The server side encryption configuration was not found',
            code: 'ServerSideEncryptionConfigurationNotFoundError'
        }
    };
}

/**
 * Builds a collection cache in the same shape as a real CloudSploit
 * collector run, containing all APIs required by the three plugins.
 */
function buildCache() {
    var getBucketTagging = {};
    var getBucketEncryption = {};
    var getBucketLocation = {};
    var getBucketWebsite = {};

    buckets.forEach(function(bucket) {
        getBucketTagging[bucket.Name] = bucketTagging(bucket.Name);
        getBucketEncryption[bucket.Name] = bucketEncryptionEntry(bucket.Name);
        getBucketLocation[bucket.Name] = {data: {LocationConstraint: REGION}};
        getBucketWebsite[bucket.Name] = {err: {code: 'NoSuchWebsiteConfiguration'}};
    });

    return {
        sts: {
            getCallerIdentity: {
                'us-east-1': {
                    data: ACCOUNT
                }
            }
        },
        ec2: {
            describeSecurityGroups: {
                'us-east-1': {data: securityGroups}
            },
            describeNetworkInterfaces: {
                'us-east-1': {data: []}
            },
            describeVolumes: {
                'us-east-1': {data: volumes}
            }
        },
        lambda: {
            listFunctions: {
                'us-east-1': {data: []}
            }
        },
        kms: {
            listKeys: {
                'us-east-1': {data: [{KeyId: 'key-ok', KeyArn: kmsKey.KeyMetadata.Arn}]}
            },
            describeKey: {
                'us-east-1': {
                    'key-ok': {data: kmsKey}
                }
            },
            listAliases: {
                'us-east-1': {data: []}
            }
        },
        s3: {
            listBuckets: {
                'us-east-1': {data: buckets.map(function(b) { return {Name: b.Name}; })}
            },
            getBucketTagging: {'us-east-1': getBucketTagging},
            getBucketEncryption: {'us-east-1': getBucketEncryption},
            getBucketLocation: {'us-east-1': getBucketLocation},
            getBucketWebsite: {'us-east-1': getBucketWebsite}
        },
        cloudfront: {
            listDistributions: {
                'us-east-1': {data: []}
            }
        }
    };
}

/**
 * Ground truth keyed by the exact resource ARN produced by each plugin.
 */
var groundTruth = {};
groundTruth[sgArn('sg-fp-001')] = 'false_positive';
groundTruth[sgArn('sg-fp-002')] = 'false_positive';
groundTruth[sgArn('sg-tp-001')] = 'true_positive';
groundTruth[volArn('vol-fp-001')] = 'false_positive';
groundTruth[volArn('vol-tp-001')] = 'true_positive';
groundTruth[bucketArn('fp-bucket-001')] = 'false_positive';
groundTruth[bucketArn('tp-bucket-001')] = 'true_positive';

/**
 * False-positive suppression rules under test. Rules are scoped by tags
 * and time windows so they only match the acknowledged resources.
 */
var suppressionRules = [
    {
        id: 'fp-pentest-ssh',
        reason: 'Authorized penetration test jump box',
        plugin: 'openSSH',
        tags: {'fp-acknowledged': 'true'},
        start: '2026-01-01T00:00:00Z',
        end: '2026-12-31T23:59:59Z'
    },
    {
        id: 'fp-temp-migration-sg',
        reason: 'Temporary migration security group',
        plugin: 'openSSH',
        tags: {environment: 'temp-*'},
        start: '2026-01-01T00:00:00Z',
        end: '2026-12-31T23:59:59Z'
    },
    {
        id: 'fp-ephemeral-ebs',
        reason: 'Ephemeral testing volume with encryption exception',
        plugin: 'ebsEncryptionEnabled',
        tags: {'exception-approved': '*'},
        start: '2026-01-01T00:00:00Z',
        end: '2026-12-31T23:59:59Z'
    },
    {
        id: 'fp-s3-migration',
        reason: 'Migration bucket with temporary encryption exception',
        plugin: 'bucketEncryption',
        tags: {'exception-approved': 'migration'},
        start: '2026-01-01T00:00:00Z',
        end: '2026-12-31T23:59:59Z'
    }
];

module.exports = {
    ACCOUNT: ACCOUNT,
    REGION: REGION,
    buildCache: buildCache,
    groundTruth: groundTruth,
    suppressionRules: suppressionRules,
    arns: {
        sg: sgArn,
        vol: volArn,
        bucket: bucketArn
    }
};
