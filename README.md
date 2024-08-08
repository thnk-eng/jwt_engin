# JwtEngin

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

## Usage

```ruby
# Gemfile
gem 'jwt_engin', path: 'path/to/jwt_engin'
```

```ruby
# config/routes.rb
Rails.application.routes.draw do
  mount JwtEngin::Engine => "/auth"
  
  namespace :api do
    resources :messages, only: [:create]
  end
end
```

```ruby
# app/controllers/application_controller.rb
class ApplicationController < ActionController::API # OR < ActionController::Base
  include JwtEngin::Authenticable
end
```

```ruby
# config/initializers/jwt_engin.rb
JwtEngin.setup do |config|
  config.token_lifetime = 2.days # Customize token lifetime
end
```
