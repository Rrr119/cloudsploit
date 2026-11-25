/**
 * Alert confidence grading.
 *
 * Confidence is a post-processing annotation layered on top of the
 * existing plugin result contract (status/message/region/resource). It
 * never changes a plugin's status, so every existing plugin keeps working
 * unchanged and the exit-code behavior is preserved.
 *
 * Grading policy:
 *  - OK (0) and UNKNOWN (3) results inherit neutral labels.
 *  - FAIL (2) starts at a high baseline and can be downgraded when signals
 *    indicate a likely false positive (explicit suppression-exempt tags are
 *    not required; this is purely advisory).
 *  - WARN (1) starts at medium.
 *  - Signals: suppression-rule-adjacent resource tags, wildcard/0.0.0.0/0
 *    exposure language in the message, and plugin-provided hints.
 *
 * Levels: high (>=80), medium (50-79), low (<50).
 */

var LEVELS = {
    HIGH: 'high',
    MEDIUM: 'medium',
    LOW: 'low'
};

var BASELINE_SCORE = {
    0: 100,
    1: 60,
    2: 90,
    3: 0
};

// Message patterns that indicate a broadly-exposed resource and therefore
// strengthen confidence in a FAIL/WARN alert.
var STRENGTHENING_PATTERNS = [
    /0\.0\.0\.0\/0/,
    /::\/0/,
    /open to the public/i,
    /all users/i,
    /is not encrypted/i,
    /unencrypted/i
];

// Resource tag keys that operations commonly use to mark accepted risk or
// temporary environments. Their presence weakens confidence slightly.
var WEAKENING_TAG_KEYS = [
    'fp-acknowledged',
    'false-positive',
    'suppress-alert',
    'temporary',
    'ephemeral',
    'exception-approved'
];

function levelForScore(score) {
    if (score >= 80) return LEVELS.HIGH;
    if (score >= 50) return LEVELS.MEDIUM;
    return LEVELS.LOW;
}

/**
 * Grades a single plugin result.
 *
 * @param {Object} result The plugin result.
 * @param {Object} [resourceTags] Tags resolved for the result resource.
 * @param {Object} [plugin] The plugin definition (used for an optional
 *   plugin-declared confidence hint).
 * @return {Object} { score, level, factors } annotation object.
 */
function grade(result, resourceTags, plugin) {
    if (!result) return null;

    // UNKNOWN is a data-collection problem, not a graded security alert.
    if (result.status === 3) {
        return {
            score: 0,
            level: 'unknown',
            factors: ['collection error; alert not gradeable']
        };
    }

    var score = BASELINE_SCORE[result.status] !== undefined ?
        BASELINE_SCORE[result.status] : 50;
    var factors = [];

    if (result.status === 0) {
        factors.push('passing result');
        return {score: score, level: LEVELS.HIGH, factors: factors};
    }

    factors.push('baseline ' + score + ' for status ' + result.status);

    var message = result.message || '';
    var strengthened = STRENGTHENING_PATTERNS.some(function(pattern) {
        return pattern.test(message);
    });
    if (strengthened) {
        score += 10;
        factors.push('+10 broad exposure / clear violation wording');
    }

    if (resourceTags) {
        var weakening = WEAKENING_TAG_KEYS.filter(function(key) {
            return Object.prototype.hasOwnProperty.call(resourceTags, key);
        });
        if (weakening.length) {
            score -= 25;
            factors.push('-25 risk-acceptance tag(s): ' + weakening.join(','));
        } else {
            score += 5;
            factors.push('+5 resource tags verified');
        }
    } else {
        score -= 5;
        factors.push('-5 no resource tags available');
    }

    // A plugin may opt into a custom confidence hint via a numeric
    // confidence_adjustment field without changing any existing interface.
    if (plugin && Number.isInteger(plugin.confidence_adjustment)) {
        score += plugin.confidence_adjustment;
        factors.push((plugin.confidence_adjustment >= 0 ? '+' : '') +
            plugin.confidence_adjustment + ' plugin hint');
    }

    score = Math.max(5, Math.min(100, score));

    return {
        score: score,
        level: levelForScore(score),
        factors: factors
    };
}

module.exports = {
    grade: grade,
    levelForScore: levelForScore,
    LEVELS: LEVELS
};
