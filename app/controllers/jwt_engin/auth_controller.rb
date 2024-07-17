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