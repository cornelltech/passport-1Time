/**
 * Module dependencies.
 */
var passport = require('passport-strategy')
  , util = require('util')
  , request = require('request');

function Strategy(options, verify) {
  if (typeof options == 'function') {
    throw new TypeError('1Time Strategy requires options');
  }
  if (!verify) { throw new TypeError('1Time Strategy requires a verify callback'); }
  if (!options.idURL) { throw new TypeError('1Time Strategy requires an idURL'); }
  if (!options.client_id) { throw new TypeError('1Time Strategy requires a client_id'); }
  if (!options.client_secret) { throw new TypeError('1Time Strategy requires a client_secret'); }

  passport.Strategy.call(this);
  this.name = '1time';
  this._verify = verify;
  this._idURL = options.idURL;
  this._client_id = options.client_id;
  this._client_secret = options.client_secret;
  this._passReqToCallback = options.passReqToCallback;
  this._code_param_name = options.code_param_name || 'code';
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);


/**
 * Authenticate request based on the contents of a HTTP Bearer authorization
 * header, body parameter, or query parameter.
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function(req) {

  console.log('authenticating in passport');
  // console.log(req.body);
  // console.log(req.query);

  var self = this;
  if (!req.body && !req.query ) {
    return this.fail(400);
  }

  var code = req.body[this._code_param_name] || req.query[this._code_param_name];
  if (!code) {
    return this.fail(400);
  }

  this._profileForCode(code, function(error, p) {

    console.log(error)
    console.log(p)

    if (error || !p) {
      return self.fail(400);
    }

    var profile = {
      provider: '1Time',
      id: p.uid,
      display_name: p.display_name
    }

    function verified(err, user, info) {
      if (err) { return self.error(err); }
      if (!user) { return self.fail(info); }
      self.success(user, info);
    }

    console.log(profile)
    try {
      if (self._passReqToCallback) {
        // console.log('calling first verify')
        self._verify(req, profile, verified);
      } else {

        // console.log('calling second verify')
        self._verify(profile, verified);
      }
    } catch (ex) {
      return self.error(ex);
    }


  });

}

Strategy.prototype._profileForCode = function(code, callback) {

  console.log(this._idURL + '/client_applications/me/login_user');
  request({
    method: 'POST',
    url: this._idURL + '/client_applications/me/login_user',
    body: {code: code},
    json: true
  }, function (error, response, body) {

      // console.log(error)
      // console.log(response)
      // console.log(body)
      if (error) {
        return callback(error, null);
      }

      if(response.statusCode == 200){
        // console.log('response body')
        // console.log(body);

        return callback(null, body);
      } else {
        console.log('error: '+ response.statusCode)
        // console.log(body)
        return callback({error: 'error: '+ response.statusCode}, null);
      }
    }).auth(this._client_id, this._client_secret);
}


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
