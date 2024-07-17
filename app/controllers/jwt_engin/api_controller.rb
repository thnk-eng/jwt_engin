module JwtEngin
  class ApiController < ApplicationController
    before_action :authenticate_request

  private

    def authenticate_request
      header = request.headers['Authorization']
      header = header.split(' ').last if header
      decoded = JwtEngin::Token.decode(header)
      @current_user = User.find(decoded[:user_id]) if decoded
    rescue ActiveRecord::RecordNotFound
      render json: { errors: 'Unauthorized' }, status: :unauthorized
    end
  end
end
