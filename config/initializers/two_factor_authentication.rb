# this will set warden.session(scope)[:need_two_factor_authentication] to true so we can 2FA the user when they sign-in
Warden::Manager.after_authentication do |user, auth, options|
  if user.respond_to?(:need_two_factor_authentication?)
    auth.session(options[:scope])[:need_two_factor_authentication] = user.need_two_factor_authentication?(auth.request)
  end
end
