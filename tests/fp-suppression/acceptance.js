/**
 * False-positive suppression acceptance harness.
 *
 * Runs three unmodified production plugins (openSSH, ebsEncryptionEnabled,
 * bucketEncryption) against a labeled synthetic environment twice:
 *
 *   1. Baseline: no false-positive suppression rules.
 *   2. Suppressed: tag/time-window rules enabled.
 *
 * Acceptance criteria (asserted by acceptance.spec.js and printed here):
 *   - False-positive rate drops for every plugin (quantified below).
 *   - Zero missed true positives across every plugin.
 *   - Every suppression hit produces an audit record.
 */

var openSSH = require('../../plugins/aws/ec2/openSSH');
var ebsEncryptionEnabled = require('../../plugins/aws/ec2/ebsEncryptionEnabled');
var bucketEncryption = require('../../plugins/aws/s3/bucketEncryption');
var tagIndex = require('../../postprocess/tagIndex');
var fpSuppression = require('../../postprocess/fpSuppression');
var confidence = require('../../postprocess/confidence');
var audit = require('../../postprocess/audit');
var fixtures = require('./fixtures');

var PLUGINS = [
    {key: 'openSSH', module: openSSH},
    {key: 'ebsEncryptionEnabled', module: ebsEncryptionEnabled},
    {key: 'bucketEncryption', module: bucketEncryption}
];

function runPlugin(plugin, cache) {
    return new Promise(function(resolve, reject) {
        plugin.module.run(cache, {}, function(err, results) {
            if (err) return reject(err);
            resolve(results || []);
        });
    });
}

function isAlert(result) {
    return result.status === 1 || result.status === 2;
}

/**
 * Executes the full post-processing pipeline used by engine.js against the
 * synthetic cache.
 *
 * @param {Array} rules False-positive rules (empty array = baseline).
 * @param {boolean} dryRun When true, rules are evaluated/audited but alerts
 *   are not suppressed (mirrors the --no-fp-suppress flag).
 */
async function runPipeline(rules, dryRun) {
    var cache = fixtures.buildCache();
    var resourceTagIndex = tagIndex.build(cache);
    var evaluator = fpSuppression.create(rules, {
        lookup: function(resource) { return tagIndex.lookup(resourceTagIndex, resource); }
    });
    var auditHandler = audit.create();
    var now = '2026-06-15T00:00:00Z';

    var perPlugin = {};

    for (var i = 0; i < PLUGINS.length; i++) {
        var pluginEntry = PLUGINS[i];
        var rawResults = await runPlugin(pluginEntry, cache);
        var emitted = [];
        var suppressed = [];

        rawResults.forEach(function(result) {
            if (!isAlert(result)) return;

            var resourceTags = tagIndex.lookup(resourceTagIndex, result.resource);
            result.confidence = confidence.grade(result, resourceTags, pluginEntry.module);

            var match = evaluator.evaluate(pluginEntry.key, result, now);
            if (match) {
                auditHandler.record(match);
                if (!dryRun) {
                    suppressed.push({result: result, match: match});
                    return;
                }
            }
            emitted.push(result);
        });

        perPlugin[pluginEntry.key] = {
            rawAlerts: rawResults.filter(isAlert),
            emitted: emitted,
            suppressed: suppressed
        };
    }

    return {
        perPlugin: perPlugin,
        audit: auditHandler.summary(),
        invalidRules: evaluator.invalidRules
    };
}

function classify(result) {
    return fixtures.groundTruth[result.resource] || null;
}

/**
 * Computes per-plugin metrics against the ground-truth labels.
 *
 * False-positive rate = false-positive alerts / total alerts.
 * Missed true positives = labeled true positives not emitted as alerts.
 */
function metricsFor(pluginKey, pluginReport) {
    var alerts = pluginReport.emitted;
    var falsePositives = alerts.filter(function(r) {
        return classify(r) === 'false_positive';
    }).length;
    var truePositives = alerts.filter(function(r) {
        return classify(r) === 'true_positive';
    }).length;

    var pluginResourceScopes = {
        openSSH: 'security-group',
        ebsEncryptionEnabled: 'volume/',
        bucketEncryption: ':s3:::'
    };
    var scope = pluginResourceScopes[pluginKey];
    var totalLabeledTp = Object.keys(fixtures.groundTruth).filter(function(arn) {
        return fixtures.groundTruth[arn] === 'true_positive' && arn.indexOf(scope) > -1;
    }).length;

    return {
        totalAlerts: alerts.length,
        falsePositives: falsePositives,
        truePositives: truePositives,
        falsePositiveRate: alerts.length ? falsePositives / alerts.length : 0,
        suppressedCount: pluginReport.suppressed.length,
        missedTruePositives: totalLabeledTp - truePositives
    };
}

async function evaluate() {
    var baseline = await runPipeline([]);
    var suppressed = await runPipeline(fixtures.suppressionRules);

    var report = {plugins: {}, totals: {}};

    PLUGINS.forEach(function(pluginEntry) {
        report.plugins[pluginEntry.key] = {
            baseline: metricsFor(pluginEntry.key, baseline.perPlugin[pluginEntry.key]),
            suppressed: metricsFor(pluginEntry.key, suppressed.perPlugin[pluginEntry.key])
        };
    });

    var sum = function(runResult, field) {
        return PLUGINS.reduce(function(acc, p) {
            return acc + metricsFor(p.key, runResult.perPlugin[p.key])[field];
        }, 0);
    };

    report.totals = {
        baselineFpRate: sum(baseline, 'falsePositives') /
            Math.max(1, PLUGINS.reduce(function(acc, p) {
                return acc + metricsFor(p.key, baseline.perPlugin[p.key]).totalAlerts;
            }, 0)),
        suppressedFpRate: sum(suppressed, 'falsePositives') /
            Math.max(1, PLUGINS.reduce(function(acc, p) {
                return acc + metricsFor(p.key, suppressed.perPlugin[p.key]).totalAlerts;
            }, 0)),
        baselineFalsePositives: sum(baseline, 'falsePositives'),
        remainingFalsePositives: sum(suppressed, 'falsePositives'),
        missedTruePositives: sum(suppressed, 'missedTruePositives'),
        totalSuppressed: suppressed.audit.totalSuppressed
    };
    report.audit = suppressed.audit;

    return report;
}

function printReport(report) {
    console.log('\n=== False-Positive Suppression Acceptance Report ===\n');
    Object.keys(report.plugins).forEach(function(pluginKey) {
        var entry = report.plugins[pluginKey];
        console.log('Plugin: ' + pluginKey);
        console.log('  baseline   : alerts=' + entry.baseline.totalAlerts +
            ' fp=' + entry.baseline.falsePositives +
            ' fpRate=' + (entry.baseline.falsePositiveRate * 100).toFixed(1) + '%' +
            ' tp=' + entry.baseline.truePositives);
        console.log('  suppressed : alerts=' + entry.suppressed.totalAlerts +
            ' fp=' + entry.suppressed.falsePositives +
            ' fpRate=' + (entry.suppressed.falsePositiveRate * 100).toFixed(1) + '%' +
            ' tp=' + entry.suppressed.truePositives +
            ' suppressedHits=' + entry.suppressed.suppressedCount +
            ' missedTP=' + entry.suppressed.missedTruePositives);
        console.log('');
    });
    console.log('Overall FP rate: ' +
        (report.totals.baselineFpRate * 100).toFixed(1) + '% -> ' +
        (report.totals.suppressedFpRate * 100).toFixed(1) + '%');
    console.log('Missed true positives: ' + report.totals.missedTruePositives);
    console.log('Audit records: ' + report.totals.totalSuppressed);
    console.log('\nAudit detail:');
    report.audit.records.forEach(function(record) {
        console.log('  - ' + record.ruleId + ' matched ' +
            record.plugin + ' ' + record.resource + ' at ' + record.evaluatedAt);
    });
    console.log('\n====================================================\n');
}

if (require.main === module) {
    evaluate().then(function(report) {
        printReport(report);
    }).catch(function(err) {
        console.error(err);
        process.exit(1);
    });
}

module.exports = {
    runPipeline: runPipeline,
    evaluate: evaluate,
    metricsFor: metricsFor,
    printReport: printReport,
    classify: classify
};
