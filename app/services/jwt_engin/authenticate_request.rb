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
      @user || errors.add(:token, 'Invalid token') && nil
    end

    def decoded_auth_token
      @decoded_auth_token ||= TokenService.decode(http_auth_header)
    end

    def http_auth_header
      if headers['Authorization'].present?
        headers['Authorization'].split(' ').last
      else
        errors.add(:token, 'Missing token')
        nil
      end
    end

    def errors
      @errors ||= ActiveModel::Errors.new(self)
    end
  end
end

