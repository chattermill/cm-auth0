// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// This code lives at https://github.com/chattermill/cm-auth0
// All changes to be deployed via Pull Requests
// AVOID manually editing on Auth0 Web UI
// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

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

  function _isSamplProfile(profile){
    return !!profile.identities.filter(function(i) {
      return i.provider === 'samlp';
    })[0];
  }

  if (!user.email_verified && !_isSamplProfile(user)) {
    return callback(null, user, context);
  }

  const userSearchApiUrl = auth0.baseUrl + '/users';

  request({
    url: userSearchApiUrl,
    headers: { Authorization: 'Bearer ' + auth0.accessToken },
    qs: { q: `email:"${user.email}"`,  search_engine: 'v3' }
  }, function(err, response, body) {
    if (err) return callback(err);
    if (response.statusCode !== 200) return callback(new Error(body));

    const foundProfiles = JSON.parse(body);
    if (foundProfiles.length === 0){
      return callback(null, user, context);
    }

    const validProfiles = foundProfiles.filter(function(u) {
      return (u.email_verified || _isSamplProfile(u)) && (u.user_id !== user.user_id);
    });

    // in case an user has several accounts created in auth0
    if (validProfiles.length > 1) {
      return callback(new Error('Multiple user profiles already exist - cannot select base profile to link with'));
    }

    const baseProfile = validProfiles[0];
    if (!baseProfile){
      return callback(null, user, context);
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
      return callback(null, user, context);
    });
  });
}
