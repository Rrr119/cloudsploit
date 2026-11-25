var expect = require('chai').expect;
var confidence = require('./confidence');

describe('confidence', function() {
    it('grades OK results as high', function() {
        var grade = confidence.grade({status: 0, message: 'ok'});
        expect(grade.level).to.equal('high');
        expect(grade.score).to.equal(100);
    });

    it('labels UNKNOWN results as unknown and non-gradeable', function() {
        var grade = confidence.grade({status: 3, message: 'Unable to query'});
        expect(grade.level).to.equal('unknown');
        expect(grade.score).to.equal(0);
    });

    it('gives a broadly exposed FAIL a high score', function() {
        var grade = confidence.grade({
            status: 2,
            message: 'Security group has SSH:22 open to 0.0.0.0/0'
        }, {team: 'platform'});
        expect(grade.score).to.equal(100);
        expect(grade.level).to.equal('high');
    });

    it('downgrades FAILs carrying risk-acceptance tags to medium', function() {
        var grade = confidence.grade({
            status: 2,
            message: 'EBS volume is unencrypted'
        }, {'fp-acknowledged': 'true'});
        expect(grade.score).to.be.below(80);
        expect(grade.level).to.equal('medium');
        expect(grade.factors.join(' ')).to.contain('fp-acknowledged');
    });

    it('grades plain WARN as medium', function() {
        var grade = confidence.grade({status: 1, message: 'unused group'});
        expect(grade.level).to.equal('medium');
    });

    it('honors a plugin-provided confidence adjustment', function() {
        var grade = confidence.grade({status: 2, message: 'x'}, null,
            {confidence_adjustment: -30});
        expect(grade.score).to.equal(55);
        expect(grade.level).to.equal('medium');
    });
});
