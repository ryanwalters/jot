'use strict';

// Load modules

const Code = require('code');
const Hapi = require('hapi');
const Jwt = require('jsonwebtoken');
const Lab = require('lab');


// Test shortcuts

const lab = exports.lab = Lab.script();
const describe = lab.describe;
const it = lab.it;
const expect = Code.expect;


// Todo: add test cases for: tampering with payload, fail when alg different than options.alg, fail when date.now is < nbf


describe('Jot', () => {

    it('fails with no options', (done) => {

        const server = new Hapi.Server();

        server.connection();
        server.register(require('../'), (err) => {

            expect(err).to.not.exist();

            expect(() => {

                server.auth.strategy('jwt', 'jwt');
            }).to.throw(Error);

            done();
        });
    });

    it('fails with no secret defined', (done) => {

        const server = new Hapi.Server();

        server.connection();
        server.register(require('../'), (err) => {

            expect(err).to.not.exist();

            expect(() => {

                server.auth.strategy('jwt', 'jwt', {
                    cookie: 'test',
                    token: 'fancyToken'
                });
            }).to.throw(Error);

            done();
        });
    });

    it('fails with invalid options', (done) => {

        const server = new Hapi.Server();

        server.connection();
        server.register(require('../'), (err) => {

            expect(err).to.not.exist();

            expect(() => {

                server.auth.strategy('jwt', 'jwt', {
                    secret: { foo: 'bar' },
                    cookie: 123,
                    token: () => { }
                });
            }).to.throw(Error);

            done();
        });
    });

    it('passes with secret defined', (done) => {

        const server = new Hapi.Server();

        server.connection();
        server.register(require('../'), (err) => {

            expect(err).to.not.exist();

            expect(() => {

                server.auth.strategy('jwt', 'jwt', {
                    secret: 'SuperSecret!'
                });
            }).to.not.throw();

            done();
        });
    });

    it('authenticates a request using the "Authorization" header', (done) => {

        const server = new Hapi.Server();

        server.connection();
        server.register(require('../'), (err) => {

            expect(err).to.not.exist();

            const secret = 'SuperSecret!';

            server.auth.strategy('jwt', 'jwt', {
                secret: secret
            });

            const jwt = Jwt.sign({
                aud: 'user'
            }, secret);

            server.route({
                method: 'GET', path: '/secure',
                config: {
                    auth: 'jwt',
                    handler: (request, reply) => {

                        return reply('ok');
                    }
                }
            });

            server.inject({ method: 'GET', url: '/secure', headers: { 'Authorization': jwt } }, (res) => {

                expect(res.statusCode).to.equal(200);
                done();
            });
        });
    });

    it('authenticates a request token is stored in a cookie', (done) => {

        const server = new Hapi.Server();

        server.connection();
        server.register([require('../'), require('hapi-auth-cookie')], (err) => {

            expect(err).to.not.exist();

            const cookieName = 'cookie';
            const secret = 'JwtSecret!';

            server.auth.strategy('jwt', 'jwt', {
                cookie: cookieName,
                secret: secret
            });

            server.auth.strategy('session', 'cookie', {
                cookie: cookieName,
                password: 'CookiePassword!'
            });

            server.route([{
                method: 'GET', path: '/login',
                config: {
                    auth: {
                        mode: 'try',
                        strategy: 'session'
                    },
                    handler: (request, reply) => {

                        request.auth.session.set({
                            token: Jwt.sign({
                                aud: 'user'
                            }, secret)
                        });

                        return reply('ok');
                    }
                }
            }, {
                method: 'GET', path: '/secure',
                config: {
                    auth: 'jwt',
                    handler: (request, reply) => {

                        return reply('ok');
                    }
                }
            }]);

            server.inject({ method: 'GET', url: '/login' }, (res) => {

                expect(res.statusCode).to.equal(200);

                const header = res.headers['set-cookie'];

                expect(header.length).to.equal(1);

                const cookie = header[0].match(/(?:[^\x00-\x20\(\)<>@\,;\:\\"\/\[\]\?\=\{\}\x7F]+)\s*=\s*(?:([^\x00-\x20\"\,\;\\\x7F]*))/);

                server.inject({ method: 'GET', url: '/secure', headers: { cookie: cookie[0] } }, (res2) => {

                    expect(res2.statusCode).to.equal(200);
                    done();
                });
            });
        });
    });

    it('fails authentication when no token is passed', (done) => {

        const server = new Hapi.Server();

        server.connection();
        server.register(require('../'), (err) => {

            expect(err).to.not.exist();

            server.auth.strategy('jwt', 'jwt', {
                secret: 'SuperSecret!'
            });

            server.route({
                method: 'GET', path: '/secure',
                config: {
                    auth: 'jwt',
                    handler: (request, reply) => {

                        return reply('ok');
                    }
                }
            });

            server.inject({ method: 'GET', url: '/secure' }, (res) => {

                expect(res.statusCode).to.equal(401);
                done();
            });
        });
    });

    it('fails authentication when signatures do not match', (done) => {

        const server = new Hapi.Server();

        server.connection();
        server.register(require('../'), (err) => {

            expect(err).to.not.exist();

            server.auth.strategy('jwt', 'jwt', {
                secret: 'ValidSecret!'
            });

            const jwt = Jwt.sign({
                aud: 'user'
            }, 'HackerSecret!');

            server.route({
                method: 'GET', path: '/secure',
                config: {
                    auth: 'jwt',
                    handler: (request, reply) => {

                        return reply('ok');
                    }
                }
            });

            server.inject({ method: 'GET', url: '/secure', headers: { 'Authorization': jwt } }, (res) => {

                expect(res.statusCode).to.equal(401);
                done();
            });
        });
    });

    it('fails authentication when token has expired', (done) => {

        const server = new Hapi.Server();

        server.connection();
        server.register(require('../'), (err) => {

            expect(err).to.not.exist();

            const secret = 'SuperSecret!';

            server.auth.strategy('jwt', 'jwt', {
                secret: secret
            });

            const jwt = Jwt.sign({
                exp: Math.floor(Date.now() / 1000)
            }, secret);

            server.route({
                method: 'GET', path: '/secure',
                config: {
                    auth: 'jwt',
                    handler: (request, reply) => {

                        return reply('ok');
                    }
                }
            });

            setTimeout(server.inject({ method: 'GET', url: '/secure', headers: { 'Authorization': jwt } }, (res) => {

                expect(res.statusCode).to.equal(401);
                done();
            }), 1000);
        });
    });
});
