require "jwt_engin/version"
require "jwt_engin/engine"
#require_relative "jwt_engin/token"
require 'jwt_engin/authenticable'

module JwtEngin
  mattr_accessor :token_lifetime
  self.token_lifetime = 86400

  def self.setup
    yield self
  end
end

