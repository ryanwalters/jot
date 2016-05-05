# jot

[__hapi__](http://hapijs.com/) JSON Web Token (JWT) authentication plugin

[![Build Status](https://travis-ci.org/ryanwalters/jot.svg?branch=master)](https://travis-ci.org/ryanwalters/jot) [![Coverage Status](https://coveralls.io/repos/ryanwalters/jot/badge.svg?branch=master&service=github)](https://coveralls.io/github/ryanwalters/jot?branch=master)

The `'jwt'` scheme takes the following options:

Option | Type | Required | Description
------ | ---- | -------- | -----------
`secret` | string | __Yes__ | Secret key used to compute the signature
`algorithms` | array | | Algorithm(s) allowed to verify tokens. Defaults to `['HS256']`. Valid algorithms: `['HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512', 'none']`
`audience` | string | | Verify `aud` claim against this value
`cookie` | string | | Cookie name. Defaults to `sid`. Works in tandem with [`hapi-auth-cookie`](https://github.com/hapijs/hapi-auth-cookie). Must set JWT when the cookie is set. See examples below
`issuer` | string | | Verify `iss` claim against this value
`token` | string | | Name of the token set in the cookie. Defaults to `token`
`validateFunc` | function | | Function to validate the decoded token on every request

_Note:_ Storing the token in a cookie is __optional__, but recommended. You can always send the token in an `Authorization` header.

## Example:

Or check out the sample app: [massive-hapi](https://github.com/ryanwalters/massive-hapi)

```js
/* server.js */


// Register hapi-auth-cookie

server.register(require('hapi-auth-cookie'), (err) => {

    server.auth.strategy('session', 'cookie', {
        cookie: 'cookie-name',
        password: 'TheMinimumLengthOfPasswordsIs32!'
    });
});


// Register jot

server.register(require('jot'), (err) => {

    server.auth.strategy('jwt', 'jwt', {
        secret: 'ADifferentPasswordAlsoAtLeast32!',
        cookie: 'cookie-name'
    });

    server.auth.default({
        strategy: 'jwt',
        scope: ['admin']
    });
});


/* routes.js */


// Login route

server.route({
    method: 'POST',
    path: '/login',
    config: {
        auth: false,
        handler: (request, reply) => {

            // ... validate user credentials, yada yada yada ...

            // Set the token inside of the cookie

            request.cookieAuth.set(Jwt.sign({
                scope: ['admin']
            }, 'ADifferentPasswordAlsoAtLeast32!', {
                expiresIn: 60 * 60 * 2 // 2 hrs, but can be anything
            }));

            reply('ok!');
        }
    }
});


// Resource

server.route({
    method: 'GET',
    path: '/trade-secrets',
    config: {
        handler: (request, reply) => {

            // User is already authorized, time to check out those trade secrets

            reply('secrets!');
        }
    }
});
```

For more examples, check out the tests.


