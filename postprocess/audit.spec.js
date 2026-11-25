var expect = require('chai').expect;
var fs = require('fs');
var os = require('os');
var path = require('path');
var audit = require('./audit');

describe('audit', function() {
    it('records suppression hits and summarizes them', function() {
        var handler = audit.create();
        handler.record({ruleId: 'r1', plugin: 'openSSH', resource: 'sg-1', status: 2});
        handler.record({ruleId: 'r1', plugin: 'openSSH', resource: 'sg-2', status: 2});
        handler.record({ruleId: 'r2', plugin: 'bucketEncryption', resource: 'b-1', status: 2});

        var summary = handler.summary();
        expect(summary.totalSuppressed).to.equal(3);
        expect(summary.suppressedByRule).to.deep.equal({r1: 2, r2: 1});
        expect(summary.suppressedByPlugin).to.deep.equal({openSSH: 2, bucketEncryption: 1});
        expect(handler.records[0].event).to.equal('suppression_hit');
    });

    it('writes JSONL records to a file sink', function(done) {
        var file = path.join(os.tmpdir(), 'fp-audit-' + Date.now() + '.jsonl');
        var handler = audit.create(file);
        handler.record({ruleId: 'r1', plugin: 'openSSH', resource: 'sg-1', status: 2});
        handler.close(function() {
            var lines = fs.readFileSync(file, 'utf8').trim().split('\n');
            expect(lines).to.have.length(1);
            expect(JSON.parse(lines[0]).ruleId).to.equal('r1');
            fs.unlinkSync(file);
            done();
        });
    });

    it('supports an in-memory writable sink', function() {
        var buffer = {chunks: [], write: function(d) { this.chunks.push(d); }};
        var handler = audit.create(buffer);
        handler.record({ruleId: 'r1', plugin: 'p', resource: 'x', status: 2});
        expect(buffer.chunks).to.have.length(1);
        expect(JSON.parse(buffer.chunks[0]).event).to.equal('suppression_hit');
    });
});
