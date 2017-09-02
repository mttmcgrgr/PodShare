class ApplicationController < ActionController::Base

  protect_from_forgery with: :exception
  ##helper_method sets these methods as available to the view
  helper_method :current_user, :logged_in?

  private

  def current_user
    ##finds user by session_token using the token stored in cookies
    ## sets found user to current_user variable
    return nil unless session[:session_token]
    @current_user ||= User.find_by(:session_token: session[:session_token])
  end

  def logged_in?
    ## double bang operator converts output of current_user to boolean
    !!current_user
  end

  def login(user)
    ## creates new session token for user provided and saves to db, also saves new
    ## session_token in cookies, and sets the user as the current_user variable
    user.reset_session_token
    session[:session_token] = user.session_token
    @current_user = user
  end

  def logout
    ## creates new session_token for current_user and saves it to db
    ## clears token in cookies, removes current_user
    @current_user.reset_session_token
    session[:session_token] = nil
    @current_user = nil
  end

end
