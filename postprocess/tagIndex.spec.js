var expect = require('chai').expect;
var tagIndex = require('./tagIndex');

describe('tagIndex', function() {
    describe('normalizeTags', function() {
        it('normalizes Key/Value arrays', function() {
            expect(tagIndex.normalizeTags([
                {Key: 'env', Value: 'prod'},
                {Key: 'fp-acknowledged', Value: 'true'}
            ])).to.deep.equal({env: 'prod', 'fp-acknowledged': 'true'});
        });

        it('normalizes S3 TagSet payloads', function() {
            expect(tagIndex.normalizeTags({TagSet: [
                {Key: 'team', Value: 'platform'}
            ]})).to.deep.equal({team: 'platform'});
        });

        it('normalizes Azure-style Key/tagValue payloads', function() {
            expect(tagIndex.normalizeTags([
                {Key: 'environment', tagValue: 'temp-migration'}
            ])).to.deep.equal({environment: 'temp-migration'});
        });

        it('returns null for empty or missing tags', function() {
            expect(tagIndex.normalizeTags([])).to.be.null;
            expect(tagIndex.normalizeTags(null)).to.be.null;
        });
    });

    describe('build and lookup', function() {
        var cache = {
            ec2: {
                describeSecurityGroups: {
                    'us-east-1': {
                        data: [
                            {
                                GroupId: 'sg-123',
                                Arn: 'arn:aws:ec2:us-east-1:111122223333:security-group/sg-123',
                                Tags: [{Key: 'fp-acknowledged', Value: 'true'}]
                            },
                            {GroupId: 'sg-notags'}
                        ]
                    }
                },
                describeVolumes: {
                    'us-east-1': {
                        data: [
                            {
                                VolumeId: 'vol-456',
                                Tags: [{Key: 'environment', Value: 'temp-pentest'}]
                            }
                        ]
                    }
                }
            },
            s3: {
                getBucketTagging: {
                    'us-east-1': {
                        'my-bucket': {
                            data: {TagSet: [{Key: 'team', Value: 'data'}]}
                        }
                    }
                }
            }
        };

        var index;

        before(function() {
            index = tagIndex.build(cache);
        });

        it('indexes EC2 resources by ARN and bare id', function() {
            expect(index['arn:aws:ec2:us-east-1:111122223333:security-group/sg-123'])
                .to.deep.equal({'fp-acknowledged': 'true'});
            expect(index['sg-123']).to.deep.equal({'fp-acknowledged': 'true'});
            expect(index['vol-456']).to.deep.equal({environment: 'temp-pentest'});
        });

        it('indexes S3 buckets by name and ARN', function() {
            expect(index['my-bucket']).to.deep.equal({team: 'data'});
            expect(index['arn:aws:s3:::my-bucket']).to.deep.equal({team: 'data'});
        });

        it('lookups tolerate partition/account ARN differences via id suffix', function() {
            expect(tagIndex.lookup(index,
                'arn:aws-us-gov:ec2:us-gov-west-1:999:security-group/sg-123'))
                .to.deep.equal({'fp-acknowledged': 'true'});
            expect(tagIndex.lookup(index, 'arn:aws:ec2:x:1:volume/vol-456'))
                .to.deep.equal({environment: 'temp-pentest'});
        });

        it('returns null for unknown or empty resources', function() {
            expect(tagIndex.lookup(index, 'sg-missing')).to.be.null;
            expect(tagIndex.lookup(index, null)).to.be.null;
            expect(tagIndex.build(undefined)).to.deep.equal({});
        });
    });
});
