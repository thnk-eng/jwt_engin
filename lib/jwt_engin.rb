require "jwt_engin/version"
require "jwt_engin/engine"
#require_relative "jwt_engin/token"


module JwtEngin
  mattr_accessor :token_lifetime
  self.token_lifetime = 1.day

  def self.setup
    yield self
  end
end

