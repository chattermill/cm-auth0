function (user, context, callback) {
  if (user.app_metadata && user.app_metadata.use_mfa){
    context.multifactor = {
      provider: 'any',
      allowRememberBrowser: true
    };
  }
  callback(null, user, context);
}
