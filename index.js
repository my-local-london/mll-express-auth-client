const request = require('mll-api-request-node'),
  cookieParser = require('cookie-parser'),
  _ = require('lodash'),
  lastModifiedBySessionId = {};

function NoUser(message) {
  this.name = "NoUser";
  this.message = (message || "");
}
NoUser.prototype = Error.prototype;

function ForbiddenUser(message) {
  this.name = "ForbiddenUser";
  this.message = (message || "");
}
ForbiddenUser.prototype = Error.prototype;

function LoginFailed(message, apiResponseBody) {
  this.name = "LoginFailed";
  this.message = (message || "");
  this.apiResponseBody = (apiResponseBody || {});
}
LoginFailed.prototype = Error.prototype;

module.exports = {
  getClientForAuthServer: function (baseUrl, authKey) {
    "use strict";
    if (!baseUrl) {
      throw new Error('Base URL is required');
    }
    if (!authKey) {
      throw new Error('Auth Key is required (to identify yourself to the auth server)');
    }
    const auth = request.getForServer(baseUrl, {basicAuth: authKey}),
      self = {
        COOKIE_NAME: 'mll-session',
        logger: {
          error: console.error.bind(console),
          log: _.noop
        },
        errors: {
          LoginFailed: LoginFailed,
          NoUser: NoUser,
          ForbiddenUser: ForbiddenUser
        },
        login: function (usernameOrEmail, password, res) {
          return auth.post('/session', {
            credentials: {
              usernameOrEmail: usernameOrEmail,
              password: password
            }
          })
            .then(function (response) {
              const sessionKey = response.body.sessionKey;
              if (res) {
                res.cookie(self.COOKIE_NAME, sessionKey);
              }
              return response.body;
            })
            .catch(function (err) {
              throw new LoginFailed('Failed to login user', err.response.body);
            })
        },
        lookupUserBySessionKey: function (sessionKey) {
          return new Promise(function (res, rej) {
            if (sessionKey) {
              var headers = {};
              var cachedData = lastModifiedBySessionId[sessionKey];
              if (cachedData) {
                var date = cachedData.lastModified;
                headers['if-modified-since'] = date;
              }

              auth.get(['', 'session', encodeURIComponent(sessionKey)].join('/'), {}, headers)
                .then(function (response) {
                  var result = response.body;
                  lastModifiedBySessionId[sessionKey] = {
                    lastModified: response.headers['last-modified'],
                    result: result
                  };
                  res(result);
                })
                .catch(function (err) {
                  if (err.statusCode === 304) { //not really an error, just a cache hit
                    return res(cachedData.result);
                  }
                  console.error('Error looking up session', err.stack);
                  rej(err);
                })
            } else {
              res(undefined);
            }
          });
        },
        lookupSessionFromRequest: function (req) {
          return new Promise(function (res, rej) {
            const clonedReq = _.clone(req);
            cookieParser()(clonedReq, {}, function (err) {
              if (err) {
                return rej(err);
              }
              const sessionKey = clonedReq.cookies && clonedReq.cookies[self.COOKIE_NAME];
              res(sessionKey);
            });
          })
            .then(function (sessionKey) {
              return self.lookupUserBySessionKey(sessionKey);
            });
        },
        middleware: function (requiredPermissions) {
          const args = arguments;

          function noUserFound(next) {
            requiredPermissions ? next(new NoUser('No user for session key')) : next();
          }

          function attachSessionToRequest(req) {
            if (req.session) {
              return Promise.resolve();
            }
            if (req.noSession) {
              throw NoUser('No session found.');
            }
            return self.lookupSessionFromRequest(req)
              .then(function (response) {
                if (!response) {
                  req.noSession = true;
                  throw NoUser('No session found.');
                }
                req.session = response.session;
              });
          }

          return function (req, res, next) {
            attachSessionToRequest(req)
              .then(function () {
                const flatRoles = _.flatMap(req.session.roles, function (permissions, group) {
                  return _.map(permissions, function (permission) {
                    return [group, permission].join('.');
                  });
                });
                const missingPermissions = _.compact(_.map(args, function (flatRequiredPermission) {
                  if (flatRoles.indexOf(flatRequiredPermission) === -1) {
                    return flatRequiredPermission;
                  }
                }));
                if (missingPermissions.length > 0) {
                  const missingList = missingPermissions.join(', ');
                  next(new ForbiddenUser('Missing permissions: ' + missingList));
                } else {
                  next();
                }
              })
              .catch(function (err) {
                noUserFound(next);
              });
          }
        }
      }
      ;
    return self;
  }
}
;
