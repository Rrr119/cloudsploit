/**
 * Audit logging for false-positive suppression hits.
 *
 * Every time a suppression rule matches a result, the match (including the
 * rule id, matched tags and time window) is recorded. The audit trail is
 * written as JSON Lines so it can be shipped to SIEM/object storage, and a
 * summary is available in-memory for the scan report.
 */

var fs = require('fs');

/**
 * @param {string|Object} [sink] A file path to append JSONL records to, or
 *   a writable stream-like object. When omitted records stay in memory.
 */
function create(sink) {
    var records = [];
    var stream = null;

    if (sink && typeof sink === 'object' && typeof sink.write === 'function') {
        stream = sink;
    } else if (typeof sink === 'string') {
        stream = fs.createWriteStream(sink, {flags: 'a'});
    }

    function record(match) {
        var entry = Object.assign({event: 'suppression_hit'}, match);
        records.push(entry);
        if (stream) stream.write(JSON.stringify(entry) + '\n');
        return entry;
    }

    function summary() {
        var byRule = {};
        var byPlugin = {};

        records.forEach(function(entry) {
            byRule[entry.ruleId] = (byRule[entry.ruleId] || 0) + 1;
            byPlugin[entry.plugin] = (byPlugin[entry.plugin] || 0) + 1;
        });

        return {
            totalSuppressed: records.length,
            suppressedByRule: byRule,
            suppressedByPlugin: byPlugin,
            records: records
        };
    }

    function close(callback) {
        if (stream && typeof stream.end === 'function') {
            if (callback) stream.on('finish', callback);
            stream.end();
        } else if (callback) {
            callback();
        }
    }

    return {
        record: record,
        summary: summary,
        close: close,
        records: records
    };
}

module.exports = {
    create: create
};
