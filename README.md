# JwtEngin
Short description and motivation.

## Usage
How to use my plugin.

## Installation
Add this line to your application's Gemfile:

```ruby
gem "jwt_engin"
```

And then execute:
```bash
$ bundle
```

Or install it yourself as:
```bash
$ gem install jwt_engin
```

## Contributing
Contribution directions go here.

## License
The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).

````ruby
# jwt_engin.gemspec
Gem::Specification.new do |spec|
  spec.name        = "jwt_engin"
  spec.version     = "0.1.0"
  spec.authors     = ["Your Name"]
  spec.email       = ["your.email@example.com"]
  spec.summary     = "JWT authentication engine"
  spec.description = "Handles JWT authentication for Rails applications"
  spec.license     = "MIT"

  spec.files = Dir["{app,config,db,lib}/**/*", "MIT-LICENSE", "Rakefile", "README.md"]

  spec.add_dependency "rails", ">= 6.0.0"
  spec.add_dependency "jwt"
  spec.add_dependency "bcrypt"
end

# lib/jwt_engin.rb
require "jwt_engin/engine"

module JwtEngin
  mattr_accessor :token_lifetime
  self.token_lifetime = 1.day

  def self.setup
    yield self
  end
end

# lib/jwt_engin/engine.rb
module JwtEngin
  class Engine < ::Rails::Engine
    isolate_namespace JwtEngin

    config.generators do |g|
      g.test_framework :rspec
      g.fixture_replacement :factory_bot
      g.factory_bot dir: 'spec/factories'
    end
  end
end

# app/models/jwt_engin/user.rb
module JwtEngin
  class User < ApplicationRecord
    has_secure_password
    has_many :auth_tokens, dependent: :destroy

    validates :email, presence: true, uniqueness: true
    validates :password, presence: true, on: :create
  end
end

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
      self.token = JwtEngin::TokenService.encode({ user_id: user_id })
      self.expires_at = JwtEngin.token_lifetime.from_now
    end
  end
end

# app/controllers/jwt_engin/application_controller.rb
module JwtEngin
  class ApplicationController < ActionController::API
  end
end

# app/controllers/jwt_engin/auth_controller.rb
module JwtEngin
  class AuthController < ApplicationController
    def create
      user = User.find_by(email: params[:email])
      if user&.authenticate(params[:password])
        auth_token = user.auth_tokens.create!
        render json: { token: auth_token.token }
      else
        render json: { error: 'Invalid credentials' }, status: :unauthorized
      end
    end

    def destroy
      if current_user
        current_user.auth_tokens.destroy_all
        render json: { message: 'Logged out successfully' }
      else
        render json: { error: 'Not authenticated' }, status: :unauthorized
      end
    end
  end
end

# app/controllers/jwt_engin/users_controller.rb
module JwtEngin
  class UsersController < ApplicationController
    def create
      user = User.new(user_params)
      if user.save
        auth_token = user.auth_tokens.create!
        render json: { token: auth_token.token }
      else
        render json: { errors: user.errors.full_messages }, status: :unprocessable_entity
      end
    end

    private

    def user_params
      params.require(:user).permit(:email, :password, :password_confirmation)
    end
  end
end

# app/services/jwt_engin/token_service.rb
module JwtEngin
  class TokenService
    SECRET_KEY = Rails.application.credentials.secret_key_base

    def self.encode(payload)
      JWT.encode(payload, SECRET_KEY)
    end

    def self.decode(token)
      JWT.decode(token, SECRET_KEY).first
    rescue JWT::DecodeError
      nil
    end
  end
end

# config/routes.rb
JwtEngin::Engine.routes.draw do
  post 'login', to: 'auth#create'
  delete 'logout', to: 'auth#destroy'
  post 'signup', to: 'users#create'
end

# lib/jwt_engin/authenticable.rb
module JwtEngin
  module Authenticable
    extend ActiveSupport::Concern

    included do
      before_action :authenticate_request
      attr_reader :current_user
    end

    private

    def authenticate_request
      @current_user = AuthenticateRequest.call(request.headers)
      render json: { error: 'Not Authorized' }, status: 401 unless @current_user
    end
  end
end

# app/services/jwt_engin/authenticate_request.rb
module JwtEngin
  class AuthenticateRequest
    def self.call(headers = {})
      new(headers).authenticate
    end

    def initialize(headers = {})
      @headers = headers
    end

    def authenticate
      user
    end

    private

    attr_reader :headers

    def user
      @user ||= User.find(decoded_auth_token[:user_id]) if decoded_auth_token
    end

    def decoded_auth_token
      @decoded_auth_token ||= TokenService.decode(http_auth_header)
    end

    def http_auth_header
      if headers['Authorization'].present?
        headers['Authorization'].split(' ').last
      end
    end
  end
end
````


## main app

```ruby
# Gemfile
gem 'jwt_engin', path: 'path/to/jwt_engin'

# config/routes.rb
Rails.application.routes.draw do
  mount JwtEngin::Engine => "/auth"
  
  namespace :api do
    resources :messages, only: [:create]
  end
end

# app/controllers/application_controller.rb
class ApplicationController < ActionController::API
  include JwtEngin::Authenticable
end

# app/controllers/api/messages_controller.rb
module Api
  class MessagesController < ApplicationController
    def create
      # Your message creation logic
      message = current_user.messages.build(message_params)
      if message.save
        render json: { message: 'Message created successfully' }, status: :created
      else
        render json: { errors: message.errors.full_messages }, status: :unprocessable_entity
      end
    end

    private

    def message_params
      params.require(:message).permit(:body)
    end
  end
end

# config/initializers/jwt_engin.rb
JwtEngin.setup do |config|
  config.token_lifetime = 2.days # Customize token lifetime
end
```

## shopify theme

```js
// Function to handle signup
async function signup(email, password) {
  try {
    const response = await fetch('https://your-api-url.com/auth/signup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ user: { email, password } })
    });
    const data = await response.json();
    if (response.ok) {
      localStorage.setItem('jwtToken', data.token);
      return true;
    } else {
      console.error('Signup failed:', data.errors);
      return false;
    }
  } catch (error) {
    console.error('Signup error:', error);
    return false;
  }
}

// Function to handle login
async function login(email, password) {
  try {
    const response = await fetch('https://your-api-url.com/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
    const data = await response.json();
    if (response.ok) {
      localStorage.setItem('jwtToken', data.token);
      return true;
    } else {
      console.error('Login failed:', data.error);
      return false;
    }
  } catch (error) {
    console.error('Login error:', error);
    return false;
  }
}

// Function to handle logout
async function logout() {
  try {
    const response = await fetch('https://your-api-url.com/auth/logout', {
      method: 'DELETE',
      headers: {
        'Authorization': `Bearer ${localStorage.getItem('jwtToken')}`
      }
    });
    if (response.ok) {
      localStorage.removeItem('jwtToken');
      return true;
    } else {
      console.error('Logout failed');
      return false;
    }
  } catch (error) {
    console.error('Logout error:', error);
    return false;
  }
}

// Function to send a message
async function sendMessage(message) {
  try {
    const response = await fetch('https://your-api-url.com/api/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${localStorage.getItem('jwtToken')}`
      },
      body: JSON.stringify({ message: { body: message } })
    });
    const data = await response.json();
    if (response.ok) {
      console.log('Message sent successfully');
      return true;
    } else {
      console.error('Failed to send message:', data.errors);
      return false;
    }
  } catch (error) {
    console.error('Error sending message:', error);
    return false;
  }
}

// Usage in your Shopify app
document.getElementById('signupForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const email = document.getElementById('signupEmail').value;
  const password = document.getElementById('signupPassword').value;
  if (await signup(email, password)) {
    console.log('Signup successful');
    // Redirect or update UI
  }
});

document.getElementById('loginForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const email = document.getElementById('loginEmail').value;
  const password = document.getElementById('loginPassword').value;
  if (await login(email, password)) {
    console.log('Login successful');
    // Redirect or update UI
  }
});

document.getElementById('logoutButton').addEventListener('click', async () => {
  if (await logout()) {
    console.log('Logout successful');
    // Redirect or update UI
  }
});

document.getElementById('messageForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const message = document.getElementById('messageInput').value;
  if (await sendMessage(message)) {
    console.log('Message sent');
    // Clear input or update UI
  }
});
```