# jot

[__hapi__](http://hapijs.com/) JSON Web Token (JWT) authentication plugin

[![Build Status](https://travis-ci.org/ryanwalters/jot.svg?branch=master)](https://travis-ci.org/ryanwalters/jot) [![Coverage Status](https://coveralls.io/repos/ryanwalters/jot/badge.svg?branch=master&service=github)](https://coveralls.io/github/ryanwalters/jot?branch=master)

[Description]

The `'jwt'` scheme takes the following options:

* `secret` - __(required)__ _{string}_ secret key used to compute the signature.
* `algorithms` - __(optional)__ _{string, array}_ algorithm(s) to verify tokens. Defaults to `HS256`. Valid algorithms: `['HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512', 'none']`
* `cookie` - __(optional)__ _{string}_ cookie name. Defaults to `sid`. Works in tandem with [`hapi-auth-cookie`](https://github.com/hapijs/hapi-auth-cookie).
Must set JWT when the cookie is set. See examples below.
* `token` - __(optional)__ _{string}_ name of the token set in the cookie. Defaults to `token`.

_Note:_ Storing the JWT in a cookie is __optional__. You can always send the JWT in an `authentication` header.

    const Hapi = require('hapi');
    const Jwt = require('jsonwebtoken');

    const server = new Hapi.Server();

    server.connection({ port: 5000 });


    // When using an 'Authentication' header

    server.register(require('jot'), (err) => {

        server.auth.strategy('jwt', 'jwt', {
            secret: process.env.SECRET_PASSWORD // required!
        });


        // First, retrieve a token after the user logs in.

        server.route({
            method: 'GET',
            path: '/login',
            handler: (request, reply) => {

                verifyTheUser(...)
                    .then((err, user) => {

                        return reply(Jwt.sign({
                            aud: user.email,
                            exp: 1447913572248
                            scope: ['lions', 'tigers', 'bears']
                        }));
                    });
            }
        });
    });

    // To be continued...


