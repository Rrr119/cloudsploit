var expect = require('chai').expect;
var harness = require('./acceptance');
var fixtures = require('./fixtures');

describe('false-positive suppression acceptance (3 plugins)', function() {
    this.timeout(20000);

    var report;

    before(async function() {
        report = await harness.evaluate();
    });

    it('quantifies a false-positive rate drop for every plugin', function() {
        Object.keys(report.plugins).forEach(function(pluginKey) {
            var entry = report.plugins[pluginKey];
            expect(entry.baseline.falsePositiveRate,
                pluginKey + ' baseline should contain false positives').to.be.greaterThan(0);
            expect(entry.suppressed.falsePositiveRate,
                pluginKey + ' suppressed FP rate').to.equal(0);
            expect(entry.suppressed.falsePositiveRate,
                pluginKey + ' rate must not increase').to.be.below(entry.baseline.falsePositiveRate);
        });

        expect(report.totals.baselineFpRate).to.be.greaterThan(0);
        expect(report.totals.suppressedFpRate).to.equal(0);
    });

    it('never suppresses a labeled true positive (zero missed real issues)', function() {
        Object.keys(report.plugins).forEach(function(pluginKey) {
            expect(report.plugins[pluginKey].suppressed.missedTruePositives,
                pluginKey + ' missed true positives').to.equal(0);
            expect(report.plugins[pluginKey].suppressed.truePositives,
                pluginKey + ' true positives still alerted').to.be.greaterThan(0);
        });
        expect(report.totals.missedTruePositives).to.equal(0);
    });

    it('emits one audit record per suppression hit with full context', function() {
        var expectedHits = Object.keys(report.plugins).reduce(function(acc, key) {
            return acc + report.plugins[key].suppressed.suppressedCount;
        }, 0);

        expect(report.audit.totalSuppressed).to.equal(expectedHits);
        expect(expectedHits).to.equal(4);

        var ruleIds = report.audit.records.map(function(r) { return r.ruleId; });
        fixtures.suppressionRules.forEach(function(rule) {
            expect(ruleIds).to.include(rule.id);
        });

        report.audit.records.forEach(function(record) {
            expect(record.event).to.equal('suppression_hit');
            expect(record.ruleId).to.be.a('string');
            expect(record.plugin).to.be.a('string');
            expect(record.resource).to.be.a('string');
            expect(record.matchedTags).to.be.an('object');
            expect(record.window.start).to.be.a('string');
            expect(record.window.end).to.be.a('string');
            expect(record.evaluatedAt).to.be.a('string');
        });
    });

    it('annotates every emitted alert with a confidence grade', async function() {
        var run = await harness.runPipeline(fixtures.suppressionRules);
        Object.keys(run.perPlugin).forEach(function(pluginKey) {
            run.perPlugin[pluginKey].emitted.forEach(function(result) {
                expect(result.confidence).to.be.an('object');
                expect(result.confidence.level).to.be.oneOf(['high', 'medium', 'low']);
                expect(result.confidence.score).to.be.at.least(5).and.at.most(100);
            });
        });
    });

    it('does not suppress any alert in dry-run mode but still audits matches', async function() {
        var dryRun = await harness.runPipeline(fixtures.suppressionRules, true);
        var dryRunAlerts = Object.keys(dryRun.perPlugin).reduce(function(acc, key) {
            return acc + dryRun.perPlugin[key].emitted.length;
        }, 0);
        var baselineAlerts = Object.keys(report.plugins).reduce(function(acc, key) {
            return acc + report.plugins[key].baseline.totalAlerts;
        }, 0);

        expect(dryRunAlerts).to.equal(baselineAlerts);
        expect(dryRun.audit.totalSuppressed).to.equal(4);
    });

    it('re-enables alerts once a rule time window expires', async function() {
        var expired = await harness.runPipeline([
            Object.assign({}, fixtures.suppressionRules[0], {end: '2020-01-01T00:00:00Z'})
        ]);
        var openSsh = expired.perPlugin.openSSH;
        var fpStillAlerted = openSsh.emitted.some(function(result) {
            return result.resource === fixtures.arns.sg('sg-fp-001');
        });
        expect(fpStillAlerted).to.equal(true);
        expect(openSsh.suppressed.length).to.equal(0);
    });
});
