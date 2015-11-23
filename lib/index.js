'use strict';

// todo: add option.alg, default to 'hs256'

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

internals.optionsSchema = Joi.object({
    secret: Joi.string().required().allow(''),
    cookie: Joi.string().default('sid'),
    token: Joi.string().default('token')
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

            Jwt.verify(token, options.secret, (err, decoded) => {

                if (err) {
                    return reply(Boom.unauthorized(err));
                }

                console.log(decoded);

                return reply.continue({ credentials: decoded });
            });
        }
    };
};
