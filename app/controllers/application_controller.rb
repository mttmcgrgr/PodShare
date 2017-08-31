class ApplicationController < ActionController::Base

  protect_from_forgery with: :exception
  helper_method :current_user, :logged_in?

  private

  def current_user
    return nil unless session[:session_token]
    @current_user ||= User.find_by(:session_token: session[:session_token])
  end

  def logged_in?
    ## double bang operator converts output of current_user to boolean
    !!current_user
  end

  def login(user)
    user.reset_session_token
    session[:session_token] = user.session_token
    @current_user = user
  end

  def logout(user)
    user.reset_session_token
    session[:session_token] = nil
    @current_user = nil
  end

end
