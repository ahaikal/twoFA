class ApplicationController < ActionController::Base
  # Prevent CSRF attacks by raising an exception.
  # For APIs, you may want to use :null_session instead.
  protect_from_forgery with: :exception

  before_action :authenticate_user!
  before_action :handle_two_factor_authentication


  def after_sign_in_path_for(user)
    AuthService.check_two_factor_cookie(current_user, request)

    if user.is? :super_admin
      session[:user_return_to] || root_url
    elsif user.is? :admin
      session[:user_return_to] || root_url
    elsif user.is? :staff
      users_path
    elsif user.is? :user
      user_path user.id
    else
      edit_user_registration_path user
    end
  end

  def handle_two_factor_authentication
  if not request.format.nil? and request.format.html? and not devise_controller?
    Devise.mappings.keys.flatten.any? do |scope|
      if signed_in?(scope) and warden.session(scope)[:need_two_factor_authentication] and !_process_action_callbacks.any?{|c| c.filter == "skip_two_factor_authentication".to_sym}
        session["#{scope}_return_to"] = request.path if request.get?
        redirect_to main_app.two_factor_authentications_path(id: current_user.id)
        return
      end
    end
  end
end

end
