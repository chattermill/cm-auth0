// Rule links social accounts to base auth0 account

function(user, context, callback) {
  const request = require('request@2.56.0');

  function _isBaseProfile(profile) {
    return !!profile.identities.filter(function(i) {
      return i.provider === 'auth0';
    })[0];
  }

  if (_isBaseProfile(user)) {
    return callback(null, user, context);
  }

  if (!user.email_verified) {
    return callback(null, user, context);
  }

  const userSearchApiUrl = auth0.baseUrl + '/users-by-email';

  request({
    url: userSearchApiUrl,
    headers: { Authorization: 'Bearer ' + auth0.accessToken },
    qs: { email: user.email }
  }, function(err, response, body) {
    if (err) return callback(err);
    if (response.statusCode !== 200) return callback(new Error(body));

    var foundProfiles = JSON.parse(body);
    var baseProfile = foundProfiles.filter(function(u) {
      return u.email_verified && _isBaseProfile(u);
    })[0];

    if (!baseProfile) {
      return callback(new UnauthorizedError('Auth0 profile was not found for ' + user.email));
    }

    const alreadyLinked = !!baseProfile.identities.filter(function(i) {
      const userId = i.provider + '|' + i.user_id;
      return userId === user.user_id;
    })[0];

    if (alreadyLinked) {
      return callback(null, user, context);
    }

    const userApiUrl = auth0.baseUrl + '/users';
    const provider = user.identities[0].provider;
    const providerUserId = user.identities[0].user_id;

    request.post({
      url: userApiUrl + '/' + baseProfile.user_id + '/identities',
      headers: { Authorization: 'Bearer ' + auth0.accessToken },
      json: {
        provider: provider,
        user_id: providerUserId
      }
    }, function(err, response, body) {
      if (response.statusCode >= 400) {
        return callback(new Error('Error linking account: ' + response.statusMessage));
      }

      context.primaryUser = baseProfile.user_id;
      callback(null, user, context);
    });
  });
}
