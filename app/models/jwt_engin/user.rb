module JwtEngin
  class User < ApplicationRecord
    has_secure_password
    has_many :auth_tokens, dependent: :destroy

    validates :email, presence: true, uniqueness: true
    validates :shop_domain, presence: true

    # Add these lines if they're not already present
    attribute :shopify_customer_id
    attribute :shop_domain
  end
end