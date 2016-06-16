const express = require('express'),
  bodyParser = require('body-parser'),
  auth = require('../index').getClientForAuthServer('http://localhost:7809', process.env.APIKEY),
  app = express();

const items = ['event', 'organiser', 'superadmin', 'user'];

function getLoginStatus(req) {
  "use strict";
  var state = req.session ? `logged in as ${req.session.greeting}` : 'not logged in';
  return `<h4>You are ${state}</h4>`;
}

app.use(auth.middleware());

app.get('/user', function (req, res) {
  res.send(req.session || {noSession: true});
});

app.get('/', (req, res) => {
  "use strict";

  res.send([
    getLoginStatus(req),
    '<ul>',
    items.map((i) => {
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

  app.post(editUrl, [auth.middleware(`${i}.update`), bodyParser.urlencoded()], function (req, res) {
    description = req.body.description;
    res.redirect('/');
  });
});

app.get('/login', (req, res) => {
  "use strict";
  if (req.user) {
    res.send(getLoginStatus(req));
  }
  res.send('<form action="/login" method=post><label>Username or email: <input name="usernameOrEmail" value="test"/></label><label>Password: <input name="password" type="password" value="test"/></label><input type="submit" value="submit"/></form>')
});

app.post('/login', [bodyParser.urlencoded()], (req, res) => {
  "use strict";
  auth.login(req.body.usernameOrEmail, req.body.password, res)
    .then(function (data) {
      console.log('Successfully logged in', req.body.usernameOrEmail, data);
      res.send(`Logged in, try the <a href="/">Homepage</a>`);
    })
    .catch(function (err) {
      console.log('Failed to log in', req.body.usernameOrEmail, req.body.password);
      console.warn(err);
      res.redirect('/login');
    })
});

app.use(function errorHandler(err, req, res, next) {
  if (err.name === 'NoUser') {
    res.redirect('/login');
  } else if (err.name === 'ForbiddenUser') {
    res.status(403);
    res.send('403 - Forbidden.  We know who you are and you\'re not allowed in.');
  } else {
    console.error('unexpected error received', err);
    res.status(500).send('An unexpected error occurred, please try again.');
  }
});

app.listen(8765);