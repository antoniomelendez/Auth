const bodyParser = require('body-parser');
const express = require('express');
const session = require('express-session');
const User = require('./user');
const bcrypt = require('bcrypt');

const STATUS_OK = 200;
const STATUS_USER_ERROR = 422;
const BCRYPT_COST = 11;

const server = express();
// to enable parsing of json bodies for post requests
server.use(bodyParser.json());
server.use(session({
  secret: 'e5SPiqsEtjexkTj3Xqovsjzq8ovjfgVDFMfUzSmJO21dtXs4re'
}));

/* Sends the given err, a string or an object, to the client. Sets the status
 * code appropriately. */
const sendUserError = (err, res) => {
  res.status(STATUS_USER_ERROR);
  if (err && err.message) {
    res.json({ message: err.message, stack: err.stack });
  } else {
    res.json({ error: err });
  }
};

server.use('/restricted/*', (req, res, next) => {
  const { userID } = req.session;
  if (!userID) {
    sendUserError('Please login', res);
    return;
  }
  User.findById(userID, (err, user) => {
    if (err) {
      sendUserError(err, res);
      return;
    }
    req.user = user;
    next();
  });
});

const validation = (req, res, next) => {
  const { userID } = req.session;
  if (!userID) {
    sendUserError('Please login', res);
    return;
  }
  User.findById(userID, (err, user) => {
    if (err) {
      sendUserError(err, res);
      return;
    }
    req.user = user;
    next();
  });
};

server.get('/restricted/something', (req, res) => {
  res.json({ success: 'you have restricted access' });
});

server.post('/users', (req, res) => {
  const { username, password } = req.body;
  if (!password) {
    sendUserError('no password', res);
    return;
  }
  const passwordHash = bcrypt.hashSync(password, BCRYPT_COST);
  const newUser = new User({ username, passwordHash });
  newUser.save((error, user) => {
    if (error) {
      sendUserError(error, res);
      return;
    }
    res.status(STATUS_OK);
    res.json(user);
  });
});

server.post('/log-in', (req, res) => {
  const { username, password } = req.body;
  User.findOne({ username }).exec((err, user) => {
    if (err) {
      sendUserError(err, res);
      return;
    }
    if (!user) {
      sendUserError('cannot find user', res);
      return;
    }
    if (!password) {
      sendUserError('no password provided', res);
      return;
    }
    if (bcrypt.compareSync(password, user.passwordHash)) {
      req.session.userID = user.id;
      res.status(STATUS_OK);
      res.json({ success: true });
      return;
    }
    sendUserError('invalid password', res);
  });
});

// TODO: add local middleware to this route to ensure the user is logged in
server.get('/me', validation, (req, res) => {
  // Do NOT modify this route handler in any way.
  res.json(req.user);
});

module.exports = { server };
