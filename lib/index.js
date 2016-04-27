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
    audience: Joi.string(),
    cookie: Joi.string().default('sid'),
    issuer: Joi.string(),
    token: Joi.string().default('token'),
    validateFunc: Joi.func()
});

internals.implementation = (server, options) => {

    const results = Joi.validate(options, internals.optionsSchema);

    Hoek.assert(!results.error, results.error);

    const settings = results.value;

    return {
        authenticate: (request, reply) => {

            const error = Boom.unauthorized();

            error.isJot = true;

            let token = request.headers.authorization;

            if (!token && request.state[settings.cookie]) {
                token = request.state[settings.cookie][settings.token];
            }

            if (!token) {

                error.output.payload.message = 'No token found';

                return reply(error);
            }

            Jwt.verify(token, settings.secret, {
                algorithms: settings.algorithms,
                audience: settings.audience,
                issuer: settings.issuer
            }, (err, decoded) => {

                if (err) {

                    error.output.payload.message = err;

                    return reply(error);
                }

                if (!settings.validateFunc) {
                    return reply.continue({ credentials: decoded });
                }

                settings.validateFunc(request, decoded, (err, isValid, updatedCredentials) => {

                    let credentials = updatedCredentials;

                    if (err) {

                        error.output.payload.message = err;

                        return reply(error);
                    }

                    if (!isValid) {

                        error.output.payload.message = 'Token is invalid';

                        return reply(error);
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
