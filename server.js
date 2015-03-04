var Hapi = require('hapi');
var config = require('config');
// var apiV1 = require('./api/api_v1');

// Create a server with a host and port
var server = new Hapi.Server(config.hapi.options);
server.connection({ host: config.hapi.hostname, port: config.hapi.port });

server.views({
    engines: {
        jade: require('jade'),
    },
    path: './views'
});

// server.route(apiV1);

server.route({
    method: 'GET',
    path: '/',
    handler: {
        view: 'index'
    }
});

server.route({
    method: 'GET',
    path: '/{path*}',
    handler: {
        directory: { path: './public', listing: false, index: true }
    }
});

server.route({
    method: 'GET',
    path: '/resources',
    handler: {
        view: 'resources'
    }
});

server.register([
    {
        register: require('./hapi-advisories'),
        options: null
    },
    {
        register: require('good'),
        options: {
            reporters: [{
                reporter: require('good-console'),
                args: [{ log: '*', response: '*', request: '*' }]
            }]
        }
    }
], function (err) {
    if (err) { 
        console.log('Failed to load plugin: ' + err);
    } else {
        console.log('Loaded advisories');
        // Start the server
        server.start(function () {
            console.log('Started Server on port: ', config.hapi.port);
        });
    }
});


// Deal with errors
server.ext('onPreResponse', function (request, reply) {
    var response = request.response;
    if (!response.isBoom) {
        return reply.continue();
    }

    // Replace error with friendly HTML

    var error = response;
    var ctx = {
        message: (error.output.statusCode === 404 ? 'page not found' : 'something went wrong')
    };

    reply.view('error', ctx).code(error.output.statusCode);
});

