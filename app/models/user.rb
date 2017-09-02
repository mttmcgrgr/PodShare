class User < ApplicationRecord

  validates :session_token, :username, :password_digest, presence: true
  validates :password, length: { minimum: 6, allow_nil: true }
  ## adding allow_nil: true allows validation to pass when password instance variable is nil.
  ## password instance variable only needs to exist when setting or changing password

  before_validation :ensure_session_token

  attr_reader :password

  def self.find_by_credentials(username, password)
    user = User.find_by(username: username)
    return nil unless user
    user.password_is?(password) ? user : nil
  end

  def password_is?(password)
    ## takes password and hashes it, then checks to see it's same as user's
    ## password_digest
    BCrypt::Password.new(self.password_digest).is_password?(password)
  end

  def password=(password)
    ##sets password input to instance variable but does NOT save to db, just for validaing
    ## presense of password when setting or changing it
    @password = password
    self.password_digest = BCrypt::Password.create(password)
  end

  def new_session_token
    SecureRandom.urlsafe_base64
  end

  def reset_session_token
    self.session_token = new_session_token
    self.save
    self.session_token
  end

  def ensure_session_token
    self.session_token ||=new_session_token
  end

end
