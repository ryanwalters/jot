# jot

[__hapi__](http://hapijs.com/) JSON Web Token (JWT) authentication plugin

[![Build Status](https://travis-ci.org/ryanwalters/jot.svg?branch=master)](https://travis-ci.org/ryanwalters/jot) [![Coverage Status](https://coveralls.io/repos/ryanwalters/jot/badge.svg?branch=master&service=github)](https://coveralls.io/github/ryanwalters/jot?branch=master)

[Description]

The `'jwt'` scheme takes the following required options:

* `secret` - __(required)__ _{string}_ secret key used to compute the signature.
* `cookie` - __(optional)__ _{string}_ cookie name. Defaults to `sid`. Works in tandem with [`hapi-auth-cookie`](https://github.com/hapijs/hapi-auth-cookie).
Must set JWT when the cookie is set. See examples below.
* `token` - __(optional)__ _{string}_ name of the token set in the cookie. Defaults to `token`.

_Note:_ Storing the JWT in a cookie is __optional__. You can always send the JWT in an `authentication` header.

[Code examples]