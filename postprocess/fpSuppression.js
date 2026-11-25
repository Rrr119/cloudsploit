/**
 * False-positive suppression rule engine.
 *
 * Unlike the legacy regex-based suppress filter (postprocess/suppress.js),
 * these rules suppress alerts based on resource tags and explicit time
 * windows. Rules are data-driven so that operations teams can acknowledge a
 * known false positive for a tagged resource without changing any plugin.
 *
 * Rule schema (JSON file or inline array):
 * {
 *   "id": "fp-001",                     // optional, generated when omitted
 *   "reason": "Pen-test approved SG",   // human-readable justification
 *   "plugin": "openSSH",                // plugin key; "*" or omitted = all
 *   "region": "us-east-1",              // optional; "*" or omitted = all
 *   "resource": "arn:...|regex",        // optional resource regex
 *   "tags": { "fp-acknowledged": "true" }, // ALL tags must match
 *   "statuses": [1, 2],                 // optional, default [1, 2]
 *   "start": "2026-11-01T00:00:00Z",    // optional ISO-8601 window start
 *   "end": "2026-12-01T00:00:00Z",      // optional ISO-8601 window end
 *   "enabled": true                     // optional, default true
 * }
 *
 * Safety invariants:
 *  - UNKNOWN results (status 3, collection errors) are never suppressible.
 *  - Rules outside their time window do not match (expired rules revert to
 *    alerting, so a forgotten rule can never hide a real issue forever).
 *  - Every match is returned to the caller for audit logging.
 */

var SUPPRESSIBLE_STATUSES = [1, 2];

function isWildcard(value) {
    return value === undefined || value === null || value === '*' || value === '';
}

function tagMatches(ruleTags, resourceTags) {
    if (!ruleTags || !Object.keys(ruleTags).length) return false;
    if (!resourceTags) return false;

    return Object.keys(ruleTags).every(function(tagKey) {
        if (!Object.prototype.hasOwnProperty.call(resourceTags, tagKey)) return false;
        var expected = String(ruleTags[tagKey]);
        var actual = String(resourceTags[tagKey]);
        if (expected === '*') return true;
        // Exact match first, then glob-style wildcard for values such as
        // "env-*".
        if (expected === actual) return true;
        var pattern = '^' + expected.replace(/[.+^${}()|[\]\\]/g, '\\$&')
            .replace(/\*/g, '.*') + '$';
        return new RegExp(pattern).test(actual);
    });
}

function withinWindow(rule, now) {
    var current = now ? new Date(now).getTime() : Date.now();
    if (rule.start && current < new Date(rule.start).getTime()) return false;
    if (rule.end && current > new Date(rule.end).getTime()) return false;
    return true;
}

/**
 * Creates a suppression evaluator from a rules array.
 *
 * @param {Array} rules Raw rule definitions. Invalid entries are skipped
 *   and reported through the returned `invalidRules` array rather than
 *   throwing, so one bad rule cannot disable a scan.
 * @param {Object} tagIndex Resource identifier -> tags map built by
 *   postprocess/tagIndex.js.
 */
function create(rules, tagIndex) {
    var compiled = [];
    var invalidRules = [];

    (rules || []).forEach(function(rawRule, index) {
        var rule = rawRule || {};

        if (rule.enabled === false) return;

        if (!rule.tags || typeof rule.tags !== 'object' || !Object.keys(rule.tags).length) {
            invalidRules.push({rule: rule, reason: 'rule must define at least one tag', index: index});
            return;
        }

        if ((rule.start && isNaN(new Date(rule.start).getTime())) ||
            (rule.end && isNaN(new Date(rule.end).getTime()))) {
            invalidRules.push({rule: rule, reason: 'invalid time window (start/end must be ISO-8601)', index: index});
            return;
        }

        if (rule.start && rule.end && new Date(rule.start).getTime() > new Date(rule.end).getTime()) {
            invalidRules.push({rule: rule, reason: 'time window start is after end', index: index});
            return;
        }

        var resourceRegex = null;
        if (!isWildcard(rule.resource)) {
            try {
                resourceRegex = new RegExp(rule.resource);
            } catch (e) {
                invalidRules.push({rule: rule, reason: 'invalid resource regex: ' + e.message, index: index});
                return;
            }
        }

        compiled.push({
            id: rule.id || ('fp-rule-' + (index + 1)),
            reason: rule.reason || '',
            plugin: isWildcard(rule.plugin) ? null : String(rule.plugin),
            region: isWildcard(rule.region) ? null : String(rule.region),
            resourceRegex: resourceRegex,
            tags: rule.tags,
            statuses: Array.isArray(rule.statuses) && rule.statuses.length ?
                rule.statuses.map(Number) : SUPPRESSIBLE_STATUSES,
            start: rule.start || null,
            end: rule.end || null
        });
    });

    /**
     * Evaluates a single plugin result against every compiled rule.
     *
     * @param {string} pluginKey Plugin identifier (exports.js key).
     * @param {Object} result A result object as produced by a plugin.
     * @param {Date|number|string} [now] Overridable evaluation time.
     * @return {Object|null} A match descriptor (for the audit log) or null.
     */
    function evaluate(pluginKey, result, now) {
        if (!result || result.status === 3 || result.status === 0) return null;

        var resourceTags = tagIndex ? tagIndex.lookup(result.resource) : null;

        for (var i = 0; i < compiled.length; i++) {
            var rule = compiled[i];

            if (rule.plugin && rule.plugin !== pluginKey) continue;
            if (rule.region && rule.region !== (result.region || 'global')) continue;
            if (rule.statuses.indexOf(result.status) === -1) continue;
            if (rule.resourceRegex && (!result.resource || !rule.resourceRegex.test(result.resource))) continue;
            if (!tagMatches(rule.tags, resourceTags)) continue;
            if (!withinWindow(rule, now)) continue;

            return {
                ruleId: rule.id,
                reason: rule.reason,
                plugin: pluginKey,
                region: result.region || 'global',
                resource: result.resource || 'any',
                status: result.status,
                message: result.message,
                matchedTags: resourceTags,
                window: {start: rule.start, end: rule.end},
                evaluatedAt: new Date(now || Date.now()).toISOString()
            };
        }

        return null;
    }

    return {
        evaluate: evaluate,
        rules: compiled,
        invalidRules: invalidRules
    };
}

module.exports = {
    create: create,
    SUPPRESSIBLE_STATUSES: SUPPRESSIBLE_STATUSES
};
