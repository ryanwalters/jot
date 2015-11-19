'use strict';

// Load modules

const Code = require('code');
const Hapi = require('hapi');
const Jwt = require('jsonwebtoken');
const Lab = require('lab');
const Yar = require('yar');


// Test shortcuts

const lab = exports.lab = Lab.script();
const describe = lab.describe;
const it = lab.it;
const expect = Code.expect;


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
                    token: 'fancy-token'
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

    it('authenticates a request token is passed in a cookie', (done) => {

        const server = new Hapi.Server();

        server.connection();
        server.register([require('../'), require('hapi-auth-cookie')], (err) => {

            expect(err).to.not.exist();

            const cookie = 'cookie';
            const secret = 'SuperSecret!';

            server.auth.strategy('jwt', 'jwt', {
                cookie: cookie,
                secret: secret
            });

            server.auth.strategy('session', 'cookie', {
                cookie: cookie,
            })

            server.route([{
                method: 'GET', path: '/login',
                handler: (request, reply) => {

                    return reply('ok');
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

                server.inject({ method: 'GET', url: '/secure' }, (res2) => {

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
