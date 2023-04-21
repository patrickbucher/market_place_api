module Authenticable
  def current_user
    return @current_user if @current_user

    header = request.headers['Authorization']
    return nil if header.nil?

    begin
      decoded = JsonWebToken.decode(header)
    rescue JWT::VerificationError
      return nil
    end

    @current_user = User.find(decoded[:user_id]) rescue ActiveRecord::RecordNotFound
  end

  protected

  def check_login
    head :forbidden unless self.current_user
  end
end
