module JwtEngin
  class User < ApplicationRecord
    has_secure_password
    has_many :auth_tokens, dependent: :destroy

    validates :email, presence: true, uniqueness: true
    #validates :password, presence: true, on: :create
  end
end