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

date
curl http://127.0.0.1:3000/auth/twitter/callback
```

https://github.com/omniauth/omniauth/wiki

```ruby
gem 'omniauth-github', github: 'intridea/omniauth-github'
gem 'omniauth-openid', github: 'intridea/omniauth-openid'

use OmniAuth::Builder do
  provider :github, ENV['GITHUB_KEY'], ENV['GITHUB_SECRET']
  provider :openid, store: OpenID::Filesystem.new('/tmp')
end

Rails.application.config.middleware.use OmniAuth::Builder do
  requrie 'openid/store/filesystem'
  provider :github, ENV['GITHUB_KEY'], ENV['GITHUB_SECRET']
  provider :openid, store: OpenID::Store::Filesystem.new('/tmp')
end

%(get post).each do |method|
  send(method, "/auth/:provider/callback") do
    env['ominauth.auth']
  end
end

get '/auth/failure' do
  flash[:notice] = params[:message]
  redirect '/'
end


class OmniAuth::Strategies::OAuth
  def initialize(app, name, consumer_key=nil, consumer_secret=nil, consumer_options={}, options={}, &block)
    self.consumer_key = consumer_key
    self.consumer_secret = consumer_secret
    self.consumer_options = consumer_options
  end
  self.options[:open_timeout] ||= 30
  self.options[:read_timeout] ||= 30
  self.options[:authorize_params] = options[:authorize_params] || {}
end

class OmniAuth::Strategies::OAuth
  args [:consumer_key, :consumer_secret]
  option :consumer_options, {}
  options :open_timeout, 30
  options :read_timeout, 30
  options :authorize_params, {}
end

class OmniAuth::Strategies::MyStrategy < OmniAuth::Strategies::OAuth
  uid { access_token.params['user_id'] }
  info do
    {
      :first_name => raw_info['firstName'],
      :last_name => raw_info['lastName'],
      :email => raw_info['email']
    }
  end
  extra do
    {'raw_info' => raw_info}
  end
  def raw_info
    access_token.get('/info')
  end
end


use OmniAuth::Builder do
  provider :example, :setup => lambda{|env| env['omniauth.strategy'].options[:foo] = env['rack.session']['foo']}
end

use OmniAuth::Builder do
  provider :example, :form => SessionController.action(:new)
end

class SessionsController < ApplicationController
  protect_from_forgery :except => [:callback]
  def callback;
  end
end

Rails.application.config.middleware.use OmniAuth::Strategies::Facebook, 'APP_ID', 'APP_SECRET',
  {:client_options => {:ssl => {:ca_path => "/etc/ssl/certs"}}}

require "openid/fetchers"
OpenId.fetcher.ca_file = "/etc/ssl/certs/ca-certificates.crt"

use OmniAuth::Builder do
  provider :example, :setup => lambda{|env| env['omniauth.strategy'].options[:foo] = env['rack.session']['foo']}
end

use OmniAuth::Builder do
  provider :example, :from => SessionController.action(:new)
end

class SessionsController < ApplicatoinController
  protect_from_forgery :except => [:callback]
  def callback;
  end
end

Rails.application.config.middleware.use OmniAuth::Strategies::Facebook, 'APP_ID', 'APP_SECRET',
  {:client_options => {:ssl => {:ca_path => "/etc/ssl/certs"}}}
  
require "openid/fetchers"
OpenId.fetcher.ca_file = "/etc/ssl/certs/ca-certificates.crt"
```

