require "cvss_rating/version"
require "cvss_rating/cvss3_formulas"
require "cvss_rating/cvss3_metrics"
require "cvss_rating/cvss3_vectors"

module Cvss3
	class Rating
		attr_accessor :exploitability, :base, :impact

		include Cvss3Vectors

		
	end
end