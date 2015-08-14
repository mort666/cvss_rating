# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'cvss_rating/version'

Gem::Specification.new do |spec|
  spec.name          = "cvss_rating"
  spec.version       = Cvss::Rating::VERSION
  spec.authors       = ["Stephen Kapp"]
  spec.email         = ["mort666@virus.org"]
  spec.summary       = %q{CVSS Risk Rating Calculation and Vector parsing}
  spec.description   = %q{CVSS Risk Rating Calculation and Vector parsing, implements CVSS 2.0 rating}
  spec.homepage      = "https://github.com/mort666/cvss_rating"
  spec.license       = "MIT"

  spec.files         = `git ls-files -z`.split("\x0")
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 1.6"
  spec.add_development_dependency "minitest"
end
