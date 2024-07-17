require_relative "lib/jwt_engin/version"

Gem::Specification.new do |spec|
  spec.name        = "jwt_engin"
  spec.version     = JwtEngin::VERSION
  spec.authors     = ["thnkr-one"]
  spec.email       = ["jacob@thnk.com"]
  spec.homepage    = "https://github.com/thnk-eng/jwt_engine"
  spec.summary     = "Summary of JwtEngine."
  spec.description = "Description of JwtEngine."
  spec.license     = "MIT"

  # Prevent pushing this gem to RubyGems.org. To allow pushes either set the "allowed_push_host"
  # to allow pushing to a single host or delete this section to allow pushing to any host.
  #spec.metadata["allowed_push_host"] = "TODO: Set to 'http://mygemserver.com'"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/thnk-eng/jwt_engine"
  spec.metadata["changelog_uri"] = "https://github.com/thnk-eng/jwt_engine"

  spec.files = Dir.chdir(File.expand_path(__dir__)) do
    Dir["{app,config,db,lib}/**/*", "MIT-LICENSE", "Rakefile", "README.md"]
  end

  spec.add_dependency "rails", ">= 7.1.3.4"
  spec.add_dependency "faraday"
  spec.add_dependency "bcrypt"
  spec.add_dependency "jwt"
  # jwt_ngin/jwt_ngin.gemspec
  # spec.add_development_dependency 'rspec-rails'

end
