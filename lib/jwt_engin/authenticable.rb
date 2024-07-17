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