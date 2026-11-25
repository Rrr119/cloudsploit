/**
 * Integration test for the engine.js post-processing pipeline.
 *
 * The AWS collector is mocked through the require cache so the real engine
 * executes end-to-end against the synthetic fixture data, including rule
 * loading, tag indexing, suppression, confidence grading and audit output.
 */

var expect = require('chai').expect;
var fs = require('fs');
var os = require('os');
var path = require('path');
var fixtures = require('./fixtures');

var collectorPath = require.resolve('../../collectors/aws/collector.js');

describe('engine false-positive integration', function() {
    this.timeout(30000);

    var auditFile;
    var jsonFile;

    before(function() {
        // Replace the collector module in the require cache with a mock so
        // engine.js loads it without making any AWS API calls.
        require.cache[collectorPath] = {
            id: collectorPath,
            filename: collectorPath,
            loaded: true,
            exports: function(cloudConfig, options, callback) {
                callback(null, fixtures.buildCache());
            }
        };

        auditFile = path.join(os.tmpdir(), 'fp-engine-audit-' + Date.now() + '.jsonl');
        jsonFile = path.join(os.tmpdir(), 'fp-engine-out-' + Date.now() + '.json');
    });

    after(function() {
        delete require.cache[collectorPath];
    });

    it('runs the full engine with suppression rules and audit output', function(done) {
        var engine = require('../../engine');
        var settings = {
            cloud: 'aws',
            plugin: 'openSSH',
            fp_rules: path.join(__dirname, 'rules.engine.json'),
            fp_audit: auditFile,
            json: jsonFile,
            console: 'none',
            mocha: true,
            ignore_ok: true
        };

        engine({}, settings);

        setTimeout(function() {
            var lines = fs.readFileSync(auditFile, 'utf8').trim().split('\n');
            var records = lines.map(JSON.parse);
            var ruleIds = records.map(function(r) { return r.ruleId; });

            expect(records.length).to.equal(2);
            expect(ruleIds).to.include('fp-pentest-ssh');
            expect(ruleIds).to.include('fp-temp-migration-sg');

            records.forEach(function(record) {
                expect(record.event).to.equal('suppression_hit');
                expect(record.matchedTags).to.be.an('object');
                expect(record.evaluatedAt).to.be.a('string');
            });

            var emitted = JSON.parse(fs.readFileSync(jsonFile, 'utf8'));
            var resources = emitted.map(function(r) { return r.resource; });

            // The true positive remains emitted and graded.
            expect(resources).to.include(fixtures.arns.sg('sg-tp-001'));
            // Both acknowledged false positives are gone from the output.
            expect(resources).to.not.include(fixtures.arns.sg('sg-fp-001'));
            expect(resources).to.not.include(fixtures.arns.sg('sg-fp-002'));

            emitted.forEach(function(result) {
                expect(result.confidence).to.not.equal(null);
                expect(result.confidence.level).to.be.oneOf(['high', 'medium', 'low']);
            });

            fs.unlinkSync(auditFile);
            fs.unlinkSync(jsonFile);
            done();
        }, 3000);
    });
});
