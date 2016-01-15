class TwoFactorAuthenticationsController < ApplicationController
  include ApplicationHelper
  layout "sign_in"

  prepend_before_filter :authenticate_scope!
  before_filter :prepare_and_validate, :handle_two_factor_authentication

  def show
    # @user = User.find(params[:id])
    # totp = AuthService.generate_otp(current_user)
    # @qr = RQRCode::QRCode.new(totp.provisioning_uri(current_user.full_name), :size => 8, :level => :h )
    # respond_to do |format|
    #   format.html
    #   format.js {render :show, local: @qr}
    # end
  end

  def update
    code = params[:code]
    render :show and return if code.nil?
    if AuthService.verify(current_user, code)
      warden.session(resource_name)["need_two_factor_authentication"] = false
      # AuthService.set_two_factor_cookie(current_user, request)
      sign_in resource_name, resource, :bypass => true
      flash.discard
      redirect_to after_sign_in_path_for(resource)
      session.delete('user_return_to')
      resource.update_column(:second_factor_attempts_count, 0)
    else
      resource.second_factor_attempts_count += 1
      resource.save
      flash[:notice] = "Attempt failed"
      if resource.max_login_attempts?
        flash[:error] = "Access completely denied as you have reached your attempts limit"
        sign_out(resource)
        render :template => 'two_factor_authentications/max_login_attempts_reached' and return
      else
        render :show
      end
    end
  end

  def edit
    AuthService.send_code(current_user, request)
    redirect_to :back
  end

  private

  def authenticate_scope!
    self.resource = send("current_#{resource_name}")
  end

  def prepare_and_validate
    redirect_to :root and return if resource.nil?
    @limit = resource.class.max_login_attempts
    if resource.max_login_attempts?
      flash[:error] = "Access completely denied as you have reached your attempts limit"
      sign_out(resource)
      render :template => 'two_factor_authentications/max_login_attempts_reached' and return
    end
  end

  def handle_two_factor_authentication
    # need this: keep user on this page until user passes 2FA
  end

end
