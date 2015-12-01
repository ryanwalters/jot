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

internals.validAlgorithms = ['HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512', 'none'];

internals.optionsSchema = Joi.object({
    secret: Joi.string().required().allow(''),
    cookie: Joi.string().default('sid'),
    token: Joi.string().default('token'),
    algorithms: Joi.array().items(Joi.string().valid(internals.validAlgorithms)).default('HS256')
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

            Jwt.verify(token, settings.secret, { algorithms: settings.algorithms }, (err, verified) => {

                if (err) {
                    return reply(Boom.unauthorized(err));
                }


                // Need to handle nbf claim ourselves for now: https://github.com/auth0/node-jsonwebtoken/pull/102

                if (verified.nbf && verified.nbf > (Date.now() / 1000)) {
                    return reply(Boom.unauthorized('Token not yet valid.'));
                }

                return reply.continue({ credentials: verified });
            });
        }
    };
};
