const request = require('mll-api-request-node'),
  cookieParser = require('cookie-parser'),
  _ = require('lodash'),
  authChainHeader = 'x-mll-auth-chain',
  lastModifiedBySessionId = {},
  lastModifiedByApiKey = {};

function NoUser(message) {
  this.name = "NoUser";
  this.message = (message || '');
}
NoUser.prototype = Object.create(Error.prototype);

function IncorrectCredentials(message) {
  this.name = "IncorrectCredentials";
  this.message = (message || 'Incorrect Credentials Provided.');
}
IncorrectCredentials.prototype = Object.create(Error.prototype);

function ForbiddenUser(message) {
  this.name = "ForbiddenUser";
  this.message = (message || '');
}
ForbiddenUser.prototype = Object.create(Error.prototype);

function LoginFailed(message, apiResponseBody) {
  this.name = "LoginFailed";
  this.message = (message || '');
  this.apiResponseBody = (apiResponseBody || {});
}
LoginFailed.prototype = Object.create(Error.prototype);

function BadRequest(message, apiResponseBody) {
  this.name = "BadRequest";
  this.message = (message || '');
  this.apiResponseBody = (apiResponseBody || {});
}
BadRequest.prototype = Object.create(Error.prototype);

function keyValueObject(key, value) {
  const obj = {};
  if (value !== undefined) {
    obj[key] = value;
  }
  return obj;
}

function addToAuthChain(req, type, key) {
  req.authChain = req.authChain ? (';' + req.authChain) : (req.header(authChainHeader) || '');
  if (type && key) {
    req.authChain = type + ':' + key + req.authChain;
  }
}

module.exports = {
  getClientForAuthServer: function (baseUrl, authKey, optionsIn) {
    "use strict";
    const options = _.extend({}, optionsIn);
    const useApiKeys = options.supportApiKeys !== false && options.supportOnlySessionKeys !== true;
    const useSessionKeys = options.supportSessionKeys !== false && options.supportOnlyApiKeys !== true;
    const logger = options.logger || _.noop;
    if (!baseUrl) {
      throw new Error('Base URL is required');
    }
    if (!authKey) {
      throw new Error('Auth Key is required (to identify yourself to the auth server)');
    }
    const auth = request.getForServer(baseUrl, {basicAuth: authKey}),
      self = {
        AUTH_CHAIN_HEADER_NAME: authChainHeader,
        COOKIE_NAME: 'mll-session',
        logger: {
          error: console.error.bind(console),
          log: _.noop
        },
        errors: {
          LoginFailed: LoginFailed,
          NoUser: NoUser,
          IncorrectCredentials: IncorrectCredentials,
          ForbiddenUser: ForbiddenUser,
          BadRequest: BadRequest
        },
        getAuthChainHeaderForRequest: function (req) {
          return keyValueObject(authChainHeader, req.authChain || req.header(authChainHeader));
        },
        register: function (details, res) {
          const userData = _.pick(details, ['username', 'email', 'fullName', 'greeting', 'password', 'roles']);
          if (!userData.password || (!userData.username && !userData.email)) {
            throw new BadRequest('Password and username/email are required when creating an account');
          }
          return auth.post('/user', {
            action: 'create',
            user: userData
          })
            .then(function () {
              return self.login(userData.email || userData.username, userData.password, res);
            });
        },
        login: function (usernameOrEmail, password, res) {
          return auth.post('/session', {
            action: 'login',
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
              if (err.response && err.response.body.noCredentialsMatch) {
                throw new IncorrectCredentials();
              }
              throw new LoginFailed('Failed to login user', err.response && err.response.body);
            })
        },
        logout: function (req, res) {
          const sessionKey = req.session && req.session.sessionKey;
          if (!sessionKey) {
            return Promise.resolve();
          }
          return auth.delete('/session/' + encodeURIComponent(sessionKey))
            .then(function () {
              res.clearCookie(self.COOKIE_NAME);
            });
        },
        lookupSession: function (sessionKey) {
          return new Promise(function (res, rej) {
            if (sessionKey) {
              var headers = {};
              var cachedData = lastModifiedBySessionId[sessionKey];
              if (cachedData) {
                headers['if-modified-since'] = cachedData.lastModified;
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
        lookupUserByApiKey: function (apiKey, authChain) {
          return new Promise(function (res, rej) {
            if (apiKey) {
              var headers = {};
              var cachedData = lastModifiedByApiKey[apiKey];
              if (cachedData) {
                headers['if-modified-since'] = cachedData.lastModified;
              }
              const headersToSend = _.extend(keyValueObject(authChainHeader, authChain), headers);
              const fullAuthChain = encodeURIComponent(_.compact(['apikey:' + apiKey, authChain]).join(';'));

              auth.get(['', 'authchain', fullAuthChain].join('/'), {}, headersToSend)
                .then(function (response) {
                  var result = _.extend({
                    apikey: apiKey
                  }, response.body);
                  lastModifiedByApiKey[apiKey] = {
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
              return self.lookupSession(sessionKey);
            });
        },
        lookupApiKeyFromRequest: function (req) {
          console.log(req.header('authorization') || req);
          const matches = (req.header('authorization') || '').match(/^[Bb]asic ([\w\-=]+)$/);
          const key = matches && matches[1];
          return self.lookupUserByApiKey(key, req.header(authChainHeader));
        },
        middleware: function (requiredPermissions) {
          const args = arguments;

          function noUserFound(next) {
            if (!requiredPermissions) {
              return next();
            }

            const messageParts = ['No user for'];
            if (useSessionKeys) {
              messageParts.push('session');
              if (useApiKeys) {
                messageParts.push('or');
              }
            }
            if (useApiKeys) {
              messageParts.push('API');
            }

            messageParts.push('key');
            next(new NoUser(messageParts.join(' ')));
          }

          function attachSessionToRequest(req) {
            if (req.session) {
              return Promise.resolve();
            }
            if (req.noSession) {
              return Promise.reject(new NoUser('No session found.'));
            }
            if (useSessionKeys) {
              return self.lookupSessionFromRequest(req)
                .then(function (response) {
                  if (!response) {
                    req.noSession = true;
                    throw NoUser('No session found.');
                  }
                  addToAuthChain(req, 'session', response.session.sessionKey);
                  req.session = response.session;
                });
            }
            if (useApiKeys) {
              return self.lookupApiKeyFromRequest(req)
                .then(function (response) {
                  if (!response) {
                    req.noSession = true;
                    throw NoUser('No session found.');
                  }
                  addToAuthChain(req, 'apikey', response.apikey);
                  req.session = response.authchain;
                  req.session.roles = response.authchain.roles;
                });
            }
            console.error('no option of looking up api or session key');
            return Promise.reject();
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
                if (missingPermissions.length > 0 && missingPermissions.length === _.size(args)) {
                  const missingList = missingPermissions.join(', ');
                  next(new ForbiddenUser('You must have one of these permissions: ' + missingList));
                } else {
                  next();
                }
              })
              .catch(function (err) {
                noUserFound(next);
              });
          }
        }
      };
    return self;
  }
};
