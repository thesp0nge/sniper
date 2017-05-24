# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'sniper/version'

Gem::Specification.new do |spec|
  spec.name          = "sniper"
  spec.version       = Sniper::VERSION
  spec.authors       = "Paolo Perego"
  spec.email         = "paolo@codiceinsicuro.it"

  spec.summary       = "Sniper is a network discovery and reconnaissance tool"
  spec.description   = "Sniper is a network discovery and reconnaissance tool"
  spec.homepage      = "https://github.com/thesp0nge/sniper"
  spec.license       = "MIT"

  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_dependency "ruby-nmap"
  spec.add_dependency "logger-colors"
  spec.add_development_dependency "bundler", "~> 1.12"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "minitest", "~> 5.0"
end
