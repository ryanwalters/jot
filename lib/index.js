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

internals.implementation = (server, options) => {

    const results = Joi.validate(options, internals.optionsSchema);

    Hoek.assert(!results.error, results.error);

    return {
        authenticate: (request, reply) => {

            const token = request.headers.authorization || request.state[options.cookie] && request.state[options.cookie].token;

            if (!token) {
                return reply(Boom.unauthorized(null));
            }

            if (token.split('.').length !== 3) {
                return reply(Boom.unauthorized('Invalid token.'));
            }

            const decoded = Jwt.verify(token, options.secret);

            console.log(decoded);

            return reply.continue({ credentials: decoded });
        }
    }
};

internals.optionsSchema = Joi.object({
    secret: Joi.string().required().allow(''),
    cookie: Joi.string().default('sid'),
    validateFunc: Joi.func(),
    registeredClaims: Joi.object({
        iss: Joi.string(),
        sub: Joi.string(),
        aud: [Joi.string(), Joi.array().items(Joi.string())],
        exp: Joi.date().min('now'),
        nbf: Joi.date().max(Joi.ref('exp')),
        iat: Joi.date(),
        jti: Joi.string()
    }),
    publicClaims: Joi.object()
});