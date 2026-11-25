var expect = require('chai').expect;
var fpSuppression = require('./fpSuppression');

var rules = [
    {
        id: 'rule-tags',
        reason: 'pen test window',
        plugin: 'openSSH',
        tags: {'fp-acknowledged': 'true'},
        start: '2026-01-01T00:00:00Z',
        end: '2026-12-31T23:59:59Z'
    },
    {
        id: 'rule-glob',
        plugin: '*',
        tags: {environment: 'temp-*'},
        statuses: [1]
    },
    {
        id: 'rule-expired',
        plugin: 'openSSH',
        tags: {'fp-acknowledged': 'true'},
        end: '2020-01-01T00:00:00Z'
    },
    {
        id: 'rule-no-tags'
    },
    {
        id: 'rule-bad-window',
        tags: {a: 'b'},
        start: 'not-a-date'
    },
    {
        id: 'rule-disabled',
        enabled: false,
        tags: {'fp-acknowledged': 'true'}
    },
    {
        id: 'rule-regex',
        tags: {'exception-approved': '*'},
        resource: 'arn:aws:ec2:.*:volume/vol-.*'
    }
];

var tagIndex = {
    lookup: function(resource) {
        if (resource === 'arn:aws:ec2:us-east-1:1:security-group/sg-ack') {
            return {'fp-acknowledged': 'true', environment: 'prod'};
        }
        if (resource === 'arn:aws:ec2:us-east-1:1:volume/vol-123') {
            return {'exception-approved': 'yes'};
        }
        if (resource === 'arn:aws:ec2:us-east-1:1:security-group/sg-temp') {
            return {environment: 'temp-pentest'};
        }
        return null;
    }
};

describe('fpSuppression', function() {
    var evaluator;

    before(function() {
        evaluator = fpSuppression.create(rules, tagIndex);
    });

    it('skips invalid and disabled rules and reports them', function() {
        expect(evaluator.rules.map(function(r) { return r.id; }))
            .to.deep.equal(['rule-tags', 'rule-glob', 'rule-expired', 'rule-regex']);
        expect(evaluator.invalidRules.map(function(e) { return e.rule.id; }))
            .to.deep.equal(['rule-no-tags', 'rule-bad-window']);
    });

    it('suppresses a FAIL result whose resource tag matches within the window', function() {
        var result = {
            status: 2,
            region: 'us-east-1',
            resource: 'arn:aws:ec2:us-east-1:1:security-group/sg-ack',
            message: 'SSH open to 0.0.0.0/0'
        };
        var match = evaluator.evaluate('openSSH', result, '2026-06-01T00:00:00Z');
        expect(match).to.not.be.null;
        expect(match.ruleId).to.equal('rule-tags');
        expect(match.matchedTags['fp-acknowledged']).to.equal('true');
    });

    it('does not suppress when the rule window has expired', function() {
        var result = {
            status: 2,
            region: 'us-east-1',
            resource: 'arn:aws:ec2:us-east-1:1:security-group/sg-ack',
            message: 'SSH open'
        };
        var match = evaluator.evaluate('openSSH', result, '2026-06-01T00:00:00Z');
        expect(match.ruleId).to.equal('rule-tags');

        var expiredRules = fpSuppression.create([rules[2]], tagIndex);
        expect(expiredRules.evaluate('openSSH', result, '2026-06-01T00:00:00Z')).to.be.null;
    });

    it('does not suppress when the resource lacks matching tags', function() {
        var result = {
            status: 2,
            region: 'us-east-1',
            resource: 'arn:aws:ec2:us-east-1:1:security-group/sg-real',
            message: 'SSH open'
        };
        expect(evaluator.evaluate('openSSH', result, '2026-06-01T00:00:00Z')).to.be.null;
    });

    it('never suppresses UNKNOWN (status 3) results', function() {
        var result = {
            status: 3,
            region: 'us-east-1',
            resource: 'arn:aws:ec2:us-east-1:1:security-group/sg-ack',
            message: 'Unable to query'
        };
        expect(evaluator.evaluate('openSSH', result, '2026-06-01T00:00:00Z')).to.be.null;
    });

    it('never suppresses OK (status 0) results', function() {
        var result = {
            status: 0,
            region: 'us-east-1',
            resource: 'arn:aws:ec2:us-east-1:1:security-group/sg-ack',
            message: 'ok'
        };
        expect(evaluator.evaluate('openSSH', result, '2026-06-01T00:00:00Z')).to.be.null;
    });

    it('respects the rule status filter', function() {
        var failResult = {
            status: 2,
            region: 'us-east-1',
            resource: 'arn:aws:ec2:us-east-1:1:security-group/sg-temp',
            message: 'warning'
        };
        var warnResult = Object.assign({}, failResult, {status: 1});
        expect(evaluator.evaluate('somePlugin', failResult, '2026-06-01T00:00:00Z')).to.be.null;
        var match = evaluator.evaluate('somePlugin', warnResult, '2026-06-01T00:00:00Z');
        expect(match.ruleId).to.equal('rule-glob');
    });

    it('matches glob tag values and resource regexes', function() {
        var result = {
            status: 2,
            region: 'us-east-1',
            resource: 'arn:aws:ec2:us-east-1:1:volume/vol-123',
            message: 'unencrypted'
        };
        var match = evaluator.evaluate('ebsEncryptionEnabled', result, '2026-06-01T00:00:00Z');
        expect(match).to.not.be.null;
        expect(match.ruleId).to.equal('rule-regex');
    });

    it('returns null when no rules are provided', function() {
        var empty = fpSuppression.create([], tagIndex);
        expect(empty.evaluate('openSSH', {status: 2, resource: 'x'}, '2026-06-01T00:00:00Z')).to.be.null;
    });
});
