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