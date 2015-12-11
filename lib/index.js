'use strict';

// Load modules

const Boom = require('boom');
const Hoek = require('hoek');
const Joi = require('joi');
const Jwt = require('jsonwebtoken');


// Declare internals

const internals = {};


// Plugin

exports.register = (server, options, next) => {

    server.auth.scheme('jwt', internals.implementation);
    next();
};

exports.register.attributes = {
    pkg: require('../package.json')
};

internals.algorithms = ['HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512', 'none'];

internals.optionsSchema = Joi.object({
    secret: Joi.string().required().allow(''),
    algorithms: Joi.array().items(Joi.string().valid(internals.algorithms)).default('HS256'),
    cookie: Joi.string().default('sid'),
    token: Joi.string().default('token'),
    validateFunc: Joi.func()
});

internals.implementation = (server, options) => {

    const results = Joi.validate(options, internals.optionsSchema);

    Hoek.assert(!results.error, results.error);

    const settings = results.value;

    return {
        authenticate: (request, reply) => {

            let token = request.headers.authorization;

            if (!token && request.state[settings.cookie]) {
                token = request.state[settings.cookie][settings.token];
            }

            if (!token) {
                return reply(Boom.unauthorized('No token found.'));
            }

            Jwt.verify(token, settings.secret, { algorithms: settings.algorithms }, (err, decoded) => {

                if (err) {
                    return reply(Boom.unauthorized(err));
                }


                // Need to handle nbf claim ourselves for now: https://github.com/auth0/node-jsonwebtoken/pull/102

                if (decoded.nbf && decoded.nbf > (Date.now() / 1000)) {
                    return reply(Boom.unauthorized('Token not yet valid.'));
                }


                if (!settings.validateFunc) {
                    return reply.continue({ credentials: decoded });
                }

                settings.validateFunc(request, decoded, (err, isValid, updatedCredentials) => {

                    let credentials = updatedCredentials;

                    if (err) {
                        return reply(Boom.unauthorized(err));
                    }

                    if (!isValid) {
                        return reply(Boom.unauthorized('Token is invalid.'));
                    }

                    if (!credentials) {
                        credentials = decoded;
                    }

                    return reply.continue({ credentials: credentials });
                });
            });
        }
    };
};
