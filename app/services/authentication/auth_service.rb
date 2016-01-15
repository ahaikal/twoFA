module AuthService
  include Rails.application.routes.url_helpers
  extend self

  TWILIO_NUMBERS = ENV.fetch('TWILIO_NUMBERS').split(/,\s?/)

  # needed for Rails.application.routes.url_helpers to work with rails 4,
  def self.default_url_options
    ActionMailer::Base.default_url_options
  end

  def generate_otp(user)
    ROTP::TOTP.new(user.second_factor_secure_code, issuer: "Kipu Systems")
  end

  def verify(user, code)
    if code.size > 6 
      user.keys.pluck(:registered_yubikey).include?(code[0..11])
    else
      totp = ROTP::TOTP.new(user.second_factor_secure_code)
      totp.verify_with_drift(code, 60)
    end
  end

  # determ which operating system the user is running
  def determ_os(request)
    @browser = request.user_agent

    if @browser.match("Macintosh")
      @os = "Macintosh"
    elsif @browser.match("iPhone")
      @os = "Iphone"
    elsif @browser.match("Windows")
      @os = "Windows"
    elsif @browser.match("Linux")
      @os = "Linux"
    elsif @browser.match("Android")
      @os = "Android"
    else
      @os = "Other"
    end

    return @os
  end

  #determining which browser user is running
  def determ_agent(request)
    @browser = request.user_agent

    if @browser.match("Chrome")
      @agent = "Chrome"
    elsif @browser.match("Safari")
      @agent = "Safari"
    elsif @browser.match("Firefox")
      @agent = "Firefox"
    elsif @browser.match("Internet Explorer") # DO NOT FIX TO 'MSIE' unless it will work with our clients existing cookies
      @agent = "InternetExplorer"
    elsif @browser.match("Opera")
      @agent = "Opera"
    else
      @agent = "Other"
    end

    return @agent
  end

  # used in the two_factor_authentication controller
  def set_two_factor_cookie(current_user, request)
    cookies = request.cookie_jar
    require 'digest/sha1'
    @two_factor_cookie_name = 'KIPU_CAS_'+ (current_user.id).to_s + '_Auth'
    @secret_cookie = Digest::SHA1.hexdigest(AuthService.determ_os(request) + AuthService.determ_agent(request) + (current_user.id).to_s)
    cookies[@two_factor_cookie_name] = {
      :value => @secret_cookie,
      :expires => 5.years.from_now,
      :domain => :all
    }
  end

  def check_two_factor_cookie(current_user, request)
    cookies = request.cookie_jar
    @two_factor_cookie_name = 'KIPU_CAS_'+ (current_user.id).to_s + '_Auth'
    require 'digest/sha1'
    @secret_cookie = Digest::SHA1.hexdigest(AuthService.determ_os(request) + AuthService.determ_agent(request) + (current_user.id).to_s)
    if (cookies[@two_factor_cookie_name].present? == true) && cookies[@two_factor_cookie_name] != @secret_cookie
      cookies.delete(@two_factor_cookie_name, :domain => :all) unless cookies[@two_factor_cookie_name] == nil
      response_redirect(destroy_user_session_path(current_user), "error", "The Cookie has been tampered with", request)
    end
  end

  def response_redirect(path, msg_key, msg, request)
    # delete any previous flash
    request.flash.discard
    request.flash[msg_key.to_sym] = msg
    response = Rack::Response.new
    response.redirect path
    throw :warden, response.finish
  end

  def send_code(current_user, request)

    @client = Twilio::REST::Client.new(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
    @account = @client.account
    body = "Your Kipu Systems Security code: #{AuthService.generate_otp(current_user).now}"
    twilio_number = TWILIO_NUMBERS.sample

    case current_user.notification_preference
    when 0
      UserMailer.two_factor_authentication(current_user.email, body).deliver

    when 1
      if !current_user.mobile.blank? && current_user.mobile.gsub(/[^0-9]/, '').length > 9
        @account.sms.messages.create(from: twilio_number, to: '+1'+ clean_phone_number(current_user.mobile) ,  body: body)
      else
        response_redirect(destroy_user_session_path(current_user),
                          "error", "Sorry, but there is no valid phone number registered with your account.", request)
      end

    when 2
      if !current_user.mobile.blank? && current_user.mobile.gsub(/[^0-9]/, '').length > 9
        @account.sms.messages.create(from: twilio_number, to: '+1'+ clean_phone_number(current_user.mobile) ,  body: body)
      end
      UserMailer.two_factor_authentication(current_user.email, body).deliver

    else
      response_redirect(destroy_user_session_path(current_user),
                        "error", "Sorry, but your account's notification preferences are not setup.", request)
    end
  end

  def clean_phone_number(phone_number)
    if phone_number.blank?
      return nil
    else
      phone_number = phone_number.gsub(/[^0-9]/, '')
      # if 11 digit format with 1
      phone_number = phone_number.drop(1) if phone_number.size == 11 && phone_number[0] == 1
      return phone_number
    end
  end


end
