require 'request_store'

class User < ActiveRecord::Base 

  before_create :set_factor_secure_code

  def set_factor_secure_code
    self.second_factor_secure_code = ROTP::Base32.random_base32
  end

  def self.max_login_attempts
    3
  end

  def max_login_attempts?
    is_authentication_failed = second_factor_attempts_count >= self.class.max_login_attempts

    if is_authentication_failed
      self.enabled = false
      self.save
    end
    is_authentication_failed
  end

  def need_two_factor_authentication?(request)
    true
  end

  def active_for_authentication?
    super && enabled?
  end

end
