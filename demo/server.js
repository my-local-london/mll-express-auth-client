const express = require('express'),
  bodyParser = require('body-parser'),
  auth = require('../index').getClientForAuthServer('http://localhost:7809', process.env.APIKEY),
  app = express(),
  bodyMiddleware = bodyParser.urlencoded({extended: true});

const items = ['event', 'organiser', 'superadmin', 'user'];

function getLoginStatus(req) {
  "use strict";
  var state = req.session ? `logged in as ${req.session.greeting}` : 'not logged in';
  return `<h4>You are ${state}</h4>`;
}

app.use(auth.middleware());

app.get('/user', function (req, res) {
  "use strict";

  res.send(req.session || {noSession: true});
});

app.get('/', (req, res) => {
  "use strict";

  res.send([
    getLoginStatus(req),
    '<ul>',
    items.concat(['apikey']).map((i) => {
      return `<li><a href="${i}">${i}</a></li>`
    }).join(''),
    '</ul>'
  ].join(''))
});

items.forEach((i) => {
  "use strict";
  const editUrl = `/${i}/edit`;
  var description = 'This is an editable description.';

  app.get(`/${i}`, [auth.middleware(`${i}.read`)], function (req, res) {
    res.send(`${getLoginStatus(req)}<h1>${i}</h1><p>${description}</p><p><a href="${editUrl}">Edit</a></p>`)
  });

  app.get(editUrl, [auth.middleware(`${i}.update`)], function (req, res) {
    res.send(`${getLoginStatus(req)}<p><a href="/">Back</a></p><form method=post action="${editUrl}"><textarea style="height: 400px; width: 100%;" name="description">
${description}</textarea><p><input type="submit" value="submit"/></p>`);
  });

  app.post(editUrl, [auth.middleware(`${i}.update`), bodyMiddleware], function (req, res) {
    description = req.body.description;
    res.redirect('/');
  });
});

app.get('/apikey', (req, res) => {
  "use strict";
  const message = req.query.success === 'true' ? '<p>The provided API Key has been looked up and the results logged on the server (to avoid leaky security).</p>' : '';
  res.send(`<h1>Lookup API Key</h1>${message}<form method="post" action="/apikey"><label>API Key <input name="apikey"/></label><input type="submit"/></form>`)
});

app.post('/apikey', [bodyMiddleware], (req, res) => {
  "use strict";
  const key = req.body.apikey;
  auth.lookupApiKey(key)
    .then(function (data) {
      console.log('API Key: ', key);
      console.log(JSON.stringify(data));
      res.redirect(req.originalUrl.split('?')[0] + '?success=true');
    })
    .catch(function (err) {
      res.send(`An error occurred: ${JSON.stringify(err.body)}`);
    });

});

app.get('/login', (req, res) => {
  "use strict";
  if (req.user) {
    res.send(getLoginStatus(req));
  }
  const message = req.query.error ? `<h3 style="color: red;">${req.query.error}</h3>` : ''; // don't do this in production, it's a XSS attach vulnerability ... but fine for a basic demo.
  res.send(`${message}<form action="/login" method=post><label>Username or email: <input name="usernameOrEmail" value="test"/></label><label>Password: <input name="password" type="password" value="test"/></label><input type="submit" value="submit"/></form>`)
});

app.post('/login', [bodyMiddleware], (req, res) => {
  "use strict";
  auth.login(req.body.usernameOrEmail, req.body.password, res)
    .then(function (data) {
      console.log('Successfully logged in', req.body.usernameOrEmail, data);
      res.send(`Logged in, try the <a href="/">Homepage</a>`);
    })
    .catch(function (err) {
      console.log('Failed to log in', req.body.usernameOrEmail, (req.body.password || '').length);
      console.warn(err.name, err.message);
      console.warn(err.stack);
      res.redirect('/login?error=' + encodeURIComponent([err.name || 'error', err.message || ''].join(': ')));
    })
});

app.use((err, req, res, next) => {
  if (err.name === 'NoUser') {
    res.redirect('/login');
  } else if (err.name === 'ForbiddenUser') {
    res.status(403);
    res.send('403 - Forbidden.  We know who you are and you\'re not allowed in.  ' + err.message);
  } else {
    console.error('unexpected error received', err);
    res.status(500).send('An unexpected error occurred, please try again.');
  }
});

app.listen(8765);
