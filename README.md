### OmniAuth
---

https://github.com/omniauth/omniauth

```ruby
require 'sinatra'
require 'omniauth'
class MyApplication < Sinatra::Base
  use Rack::Session::Cookie
  use OmniAuth::Strategies::Developer
end

Rails.application.config.middleware.use OmniAuth::Builder do
  provider :developer unless Rails.env.production?
  provider :twitter, ENV['TWITTER_KEY'], ENV['TWITTER_SECRET']
end

get '/auth/:provider/callback', to: 'sessions#create'

class SessionController < ApplicationController
  def create
    @user = User.find_of_create_from_auth_hash(auth_hash)
    self.current_user = @user
    redirect_to '/'
  end
  protected
  def auth_hash
    request.env['omniauth.auth']
  end
end

/auth/twitter/?origin=[URL]
provider :twitter, ENV['KEY'], ENV['SECRET'], origin_param: 'return_to'
provider :twitter, ENV['KEY'], origin_param:false

config.session_store :cookie, key: '_interslice_session'
config.middleware.use ActionDispatch::Cookies
config.middleware.use ActionDispatch::Session::CookieStore, config.session_options

OmniAuth.config.logger = Rails.logger

spec.add_dependency 'omniauth', '~> 1.0'


```

https://github.com/omniauth/omniauth/wiki

```
```
