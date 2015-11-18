# jot

[__hapi__](http://hapijs.com/) JSON Web Token (JWT) authentication plugin

[Description]

The `'jwt'` scheme takes the following required options:

* `secret` - __(required)__ secret key used to compute the signature.
* `cookie` - __(optional)__ cookie name. Defaults to `sid`. Works in tandem with [`hapi-auth-cookie`](https://github.com/hapijs/hapi-auth-cookie).
Must set JWT when the cookie is set. See examples below.
* `token` - __(optional)__ name of the token set in the cookie. Defaults to `token`.

_Note:_ Storing the JWT in a cookie is __optional__. You can always send the JWT in an `authentication` header.

[Code examples]