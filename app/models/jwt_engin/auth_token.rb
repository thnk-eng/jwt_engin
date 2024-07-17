# app/models/jwt_engin/auth_token.rb
module JwtEngin
  class AuthToken < ApplicationRecord
    belongs_to :user

    before_create :generate_token

    def self.active
      where('expires_at > ?', Time.current)
    end

  private

    def generate_token
      self.token = JwtEngin::TokenService.encode({ user_id: jwt_engin_user_id })
      self.expires_at = JwtEngin.token_lifetime.from_now
    end
  end
end