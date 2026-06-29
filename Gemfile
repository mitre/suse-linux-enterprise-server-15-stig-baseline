# frozen_string_literal: true

source 'https://rubygems.org'
gem 'berkshelf'
# connection_pool 3.x uses Ruby 3.4+ syntax but does not gate its
# required_ruby_version, so the resolver picks it on Ruby 3.3 and then fails to
# parse at load. Pin to 2.x to match our supported Ruby range (local + CI: 3.3).
gem 'connection_pool', '< 3'
gem 'highline'
gem 'kitchen-ansible'
gem 'kitchen-docker'
gem 'kitchen-dokken'
gem 'kitchen-ec2'
gem 'kitchen-inspec'
gem 'kitchen-sync'
gem 'kitchen-vagrant'
gem 'pry-byebug'
gem 'rake'
gem 'rubocop'
gem 'rubocop-rake'
gem 'test-kitchen'
gem 'train-awsssm'

source 'https://rubygems.cinc.sh/' do
  gem 'chef-config'
  gem 'chef-utils'
  gem 'cinc-auditor-bin'
  gem 'inspec'
  gem 'inspec-core'
end
