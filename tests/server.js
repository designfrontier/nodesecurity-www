var Hapi = require('hapi');
var advisories = require('../hapi-advisories');
var config = require('config');
var server = new Hapi.Server();
server.connection();
var valid_no_vulns = require('./data/valid_no_vulns.json');
var valid_vulns = require('./data/valid_vulns.json');
var invalid_1 = require('./data/invalid_1.json');
var invalid_2 = require('./data/invalid_2.json');
var invalid_3 = require('./data/invalid_3.json');
var valid_nested = require('./data/valid_vulns_nested.json');
var unpatched = require('./data/unpatched.json');
var semver_test = require('./data/semver_test.json');

exports['register plugin'] = function (test) {
    server.register({register: advisories, options: {views: '../views'}}, function (err) {
        test.ifError(err);
        test.done();
    });
};

exports['valid payload - no vulns'] = function (test) {
    server.inject({
        method: 'POST',
        url: '/validate/shrinkwrap',
        payload: valid_no_vulns
    }, function (res) {
        var payload;
        test.equal(res.statusCode, '200', 'should return a 200');
        test.doesNotThrow(function () {payload = JSON.parse(res.payload); });
        test.equal(res.payload, '[]', 'should return no results');
        test.done();
    });
};

exports['valid payload - vulns'] = function (test) {
    server.inject({
        method: 'POST',
        url: '/validate/shrinkwrap',
        payload: valid_vulns

    }, function (res) {
        var payload;
        test.equal(res.statusCode, '200', 'should return a 200');
        test.doesNotThrow(function () {payload = JSON.parse(res.payload); });
        test.equal(payload.length, 2);
        test.ok(payload[0].module, 'should have a module key');
        test.ok(payload[0].version, 'should have a version key');
        test.ok(payload[0].advisory, 'show have an advisory key');
        test.done();
    });
};

exports['invalid payload: no name, empty dependencies'] = function (test) {
    // No name
    // empty dependencies

    server.inject({
        method: 'POST',
        url: '/validate/shrinkwrap',
        payload: invalid_1
    }, function (res) {
        var payload;
        test.equal(res.statusCode, '200', 'should return a 200');
        test.doesNotThrow(function () {payload = JSON.parse(res.payload); });
        test.equal(res.payload, '[]', 'should return no results');
        test.done();
    });
};

exports['invalid payload: vuln module, no version'] = function (test) {

    server.inject({
        method: 'POST',
        url: '/validate/shrinkwrap',
        payload: invalid_2
    }, function (res) {
        var payload;
        test.equal(res.statusCode, '200', 'should return a 200');
        test.doesNotThrow(function () {payload = JSON.parse(res.payload); });
        test.equal(res.payload, '[]', 'should return no results');
        test.done();
    });
};

exports['invalid payload: vuln module, invalid version'] = function (test) {
    server.inject({
        method: 'POST',
        url: '/validate/shrinkwrap',
        payload: invalid_3
    }, function (res) {
        var payload;
        test.equal(res.statusCode, '200', 'should return a 200');
        test.doesNotThrow(function () {payload = JSON.parse(res.payload); });
        test.equal(res.payload, '[]', 'should return no results');
        test.done();
    });
};

exports['non existent module'] = function (test) {
    server.inject({
        method: 'GET',
        url: '/validate/herpmcderp/1.2.1'
    }, function (res) {
        var payload;
        test.equal(res.statusCode, '200', 'should return a 200');
        test.doesNotThrow(function () {payload = JSON.parse(res.payload); });
        test.equal(res.payload, '[]', 'should return no results');
        test.done();
    });
};

exports['existing module wrong version'] = function (test) {
    server.inject({
        method: 'GET',
        url: '/validate/tomato/1.2.1'
    }, function (res) {
        var payload;
        test.equal(res.statusCode, '200', 'should return a 200');
        test.doesNotThrow(function () {payload = JSON.parse(res.payload); });
        test.equal(res.payload, '[]', 'should return no results');
        test.done();
    });
};


exports['existing module invalid version'] = function (test) {
    server.inject({
        method: 'GET',
        url: '/validate/tomato/1.'
    }, function (res) {
        var payload;
        test.equal(res.statusCode, '200', 'should return a 200');
        test.doesNotThrow(function () {payload = JSON.parse(res.payload); });
        test.equal(res.payload, '[]', 'should return no results');
        test.done();
    });
};


exports['existing module vuln version'] = function (test) {
    server.inject({
        method: 'GET',
        url: '/validate/tomato/0.0.1'
    }, function (res) {
        var payload;
        test.equal(res.statusCode, '200', 'should return a 200');
        test.doesNotThrow(function () {payload = JSON.parse(res.payload); });
        test.equal(payload.length, 1);
        test.done();
    });
};

exports['Dependency Tree'] = function (test) {
    server.inject({
        method: 'POST',
        url: '/validate/shrinkwrap',
        payload: valid_nested

    }, function (res) {
        var payload;
        test.equal(res.statusCode, '200', 'should return a 200');
        test.doesNotThrow(function () {payload = JSON.parse(res.payload); });
        test.equal(payload.length, 1);
        test.ok(payload[0].module, 'should have a module key');
        test.ok(payload[0].version, 'should have a version key');
        test.ok(payload[0].advisory, 'should have an advisory key');
        test.deepEqual(payload[0].dependencyOf, ['root', 'second'], 'should have second and root as parents');
        test.done();
    });
};

exports['unpatched module'] = function (test) {
    server.inject({
        method: 'POST',
        url: '/validate/shrinkwrap',
        payload: unpatched

    }, function (res) {
        var payload;
        test.equal(res.statusCode, '200', 'should return a 200');
        test.doesNotThrow(function () {payload = JSON.parse(res.payload); });
        test.equal(payload.length, 1);
        test.ok(payload[0].module, 'should have a module key');
        test.ok(payload[0].version, 'should have a version key');
        test.ok(payload[0].advisory, 'should have an advisory key');
        //test.deepEqual(payload[0].dependencyOf, ['root', 'second'], 'should have second and root as parents');
        test.done();
    });
};


exports['semver with -rcsomething'] = function (test) {
    server.inject({
        method: 'POST',
        url: '/validate/shrinkwrap',
        payload: semver_test

    }, function (res) {
        var payload;
        test.equal(res.statusCode, '200', 'should return a 200');
        test.doesNotThrow(function () {payload = JSON.parse(res.payload); });
        test.equal(payload.length, 1);
        test.ok(payload[0].module, 'should have a module key');
        test.ok(payload[0].version, 'should have a version key');
        test.ok(payload[0].advisory, 'show have an advisory key');
        test.done();
    });
};

//API TESTS BELOW
exports['valid payload - vulns'] = function (test) {
    server.inject({
        method: 'POST',
        url: '/api/v1/validate/shrinkwrap',
        payload: valid_vulns

    }, function (res) {
        var payload;
        test.equal(res.statusCode, '200', 'should return a 200');
        test.doesNotThrow(function () {payload = JSON.parse(res.payload); });
        test.equal(payload.length, 2);
        test.ok(payload[0].module, 'should have a module key');
        test.ok(payload[0].version, 'should have a version key');
        test.ok(payload[0].advisory, 'show have an advisory key');
        test.done();
    });
};

exports['invalid payload: no name, empty dependencies'] = function (test) {
    // No name
    // empty dependencies

    server.inject({
        method: 'POST',
        url: '/api/v1/validate/shrinkwrap',
        payload: invalid_1
    }, function (res) {
        var payload;
        test.equal(res.statusCode, '200', 'should return a 200');
        test.doesNotThrow(function () {payload = JSON.parse(res.payload); });
        test.equal(res.payload, '[]', 'should return no results');
        test.done();
    });
};

exports['valid payload - no vulns'] = function (test) {
    server.inject({
        method: 'POST',
        url: '/api/v1/validate/shrinkwrap',
        payload: valid_no_vulns
    }, function (res) {
        var payload;
        test.equal(res.statusCode, '200', 'should return a 200');
        test.doesNotThrow(function () {payload = JSON.parse(res.payload); });
        test.equal(res.payload, '[]', 'should return no results');
        test.done();
    });
};

exports['valid payload - vulns'] = function (test) {
    server.inject({
        method: 'POST',
        url: '/api/v1/validate/shrinkwrap',
        payload: valid_vulns

    }, function (res) {
        var payload;
        test.equal(res.statusCode, '200', 'should return a 200');
        test.doesNotThrow(function () {payload = JSON.parse(res.payload); });
        test.equal(payload.length, 2);
        test.ok(payload[0].module, 'should have a module key');
        test.ok(payload[0].version, 'should have a version key');
        test.ok(payload[0].advisory, 'show have an advisory key');
        test.done();
    });
};

exports['invalid payload: no name, empty dependencies'] = function (test) {
    // No name
    // empty dependencies

    server.inject({
        method: 'POST',
        url: '/api/v1/validate/shrinkwrap',
        payload: invalid_1
    }, function (res) {
        var payload;
        test.equal(res.statusCode, '200', 'should return a 200');
        test.doesNotThrow(function () {payload = JSON.parse(res.payload); });
        test.equal(res.payload, '[]', 'should return no results');
        test.done();
    });
};

exports['invalid payload: vuln module, no version'] = function (test) {

    server.inject({
        method: 'POST',
        url: '/api/v1/validate/shrinkwrap',
        payload: invalid_2
    }, function (res) {
        var payload;
        test.equal(res.statusCode, '200', 'should return a 200');
        test.doesNotThrow(function () {payload = JSON.parse(res.payload); });
        test.equal(res.payload, '[]', 'should return no results');
        test.done();
    });
};

exports['invalid payload: vuln module, invalid version'] = function (test) {
    server.inject({
        method: 'POST',
        url: '/api/v1/validate/shrinkwrap',
        payload: invalid_3
    }, function (res) {
        var payload;
        test.equal(res.statusCode, '200', 'should return a 200');
        test.doesNotThrow(function () {payload = JSON.parse(res.payload); });
        test.equal(res.payload, '[]', 'should return no results');
        test.done();
    });
};

exports['non existent module'] = function (test) {
    server.inject({
        method: 'GET',
        url: '/api/v1/validate/herpmcderp/1.2.1'
    }, function (res) {
        var payload;
        test.equal(res.statusCode, '200', 'should return a 200');
        test.doesNotThrow(function () {payload = JSON.parse(res.payload); });
        test.equal(res.payload, '[]', 'should return no results');
        test.done();
    });
};

exports['existing module wrong version'] = function (test) {
    server.inject({
        method: 'GET',
        url: '/api/v1/validate/tomato/1.2.1'
    }, function (res) {
        var payload;
        test.equal(res.statusCode, '200', 'should return a 200');
        test.doesNotThrow(function () {payload = JSON.parse(res.payload); });
        test.equal(res.payload, '[]', 'should return no results');
        test.done();
    });
};


exports['existing module invalid version'] = function (test) {
    server.inject({
        method: 'GET',
        url: '/api/v1/validate/tomato/1.'
    }, function (res) {
        var payload;
        test.equal(res.statusCode, '200', 'should return a 200');
        test.doesNotThrow(function () {payload = JSON.parse(res.payload); });
        test.equal(res.payload, '[]', 'should return no results');
        test.done();
    });
};


exports['existing module vuln version'] = function (test) {
    server.inject({
        method: 'GET',
        url: '/api/v1/validate/tomato/0.0.1'
    }, function (res) {
        var payload;
        test.equal(res.statusCode, '200', 'should return a 200');
        test.doesNotThrow(function () {payload = JSON.parse(res.payload); });
        test.equal(payload.length, 1);
        test.done();
    });
};

exports['Dependency Tree'] = function (test) {
    server.inject({
        method: 'POST',
        url: '/api/v1/validate/shrinkwrap',
        payload: valid_nested

    }, function (res) {
        var payload;
        test.equal(res.statusCode, '200', 'should return a 200');
        test.doesNotThrow(function () {payload = JSON.parse(res.payload); });
        test.equal(payload.length, 1);
        test.ok(payload[0].module, 'should have a module key');
        test.ok(payload[0].version, 'should have a version key');
        test.ok(payload[0].advisory, 'should have an advisory key');
        test.deepEqual(payload[0].dependencyOf, ['root', 'second'], 'should have second and root as parents');
        test.done();
    });
};

exports['unpatched module'] = function (test) {
    server.inject({
        method: 'POST',
        url: '/api/v1/validate/shrinkwrap',
        payload: unpatched

    }, function (res) {
        var payload;
        test.equal(res.statusCode, '200', 'should return a 200');
        test.doesNotThrow(function () {payload = JSON.parse(res.payload); });
        test.equal(payload.length, 1);
        test.ok(payload[0].module, 'should have a module key');
        test.ok(payload[0].version, 'should have a version key');
        test.ok(payload[0].advisory, 'should have an advisory key');
        //test.deepEqual(payload[0].dependencyOf, ['root', 'second'], 'should have second and root as parents');
        test.done();
    });
};


exports['semver with -rcsomething'] = function (test) {
    server.inject({
        method: 'POST',
        url: '/api/v1/validate/shrinkwrap',
        payload: semver_test

    }, function (res) {
        var payload;
        test.equal(res.statusCode, '200', 'should return a 200');
        test.doesNotThrow(function () {payload = JSON.parse(res.payload); });
        test.equal(payload.length, 1);
        test.ok(payload[0].module, 'should have a module key');
        test.ok(payload[0].version, 'should have a version key');
        test.ok(payload[0].advisory, 'show have an advisory key');
        test.done();
    });
};
