# jot

[__hapi__](http://hapijs.com/) JSON Web Token (JWT) authentication plugin

[![Build Status](https://travis-ci.org/ryanwalters/jot.svg?branch=master)](https://travis-ci.org/ryanwalters/jot) [![Coverage Status](https://coveralls.io/repos/ryanwalters/jot/badge.svg?branch=master&service=github)](https://coveralls.io/github/ryanwalters/jot?branch=master)

The `'jwt'` scheme takes the following options:

* `secret` - __(required)__ _{string}_ secret key used to compute the signature.
* `algorithms` - __(optional)__ _{array}_ algorithm(s) allowed to verify tokens. Defaults to `['HS256']`. Valid algorithms: `['HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512', 'none']`
* `audience` - __(optional)__ _{string|integer}_ verify audience `(aud)` claim against this value
* `cookie` - __(optional)__ _{string}_ cookie name. Defaults to `sid`. Works in tandem with [`hapi-auth-cookie`](https://github.com/hapijs/hapi-auth-cookie).
Must set JWT when the cookie is set. See examples below.
* `issuer` - __(optional)__ _{string|integer}_ verify issuer `(iss)` claim against this value
* `token` - __(optional)__ _{string}_ name of the token set in the cookie. Defaults to `token`.
* `validateFunc` - __(optional)__ _{function}_ function to validate the decoded token on every request.

_Note:_ Storing the JWT in a cookie is __optional__. You can always send the JWT in an `Authorization` header.

For examples of usage, check out the tests.


