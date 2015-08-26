require "cvss_rating/version"
require "cvss_rating/cvss3_formulas"
require "cvss_rating/cvss3_metrics"
require "cvss_rating/cvss3_vectors"

module Cvss3
	class Rating
		attr_accessor :exploitability, :base, :impact

		include Cvss3Vectors

		def initialize(attributes = {})   
			init

	    	attributes.each do |name, value|
	      		send("#{name}=", value)
	    	end
	 	end

	 	def risk_score(score)
	 		risk_score = case score
	 			when 0.0
	 				"None"
	 			when 0.1..3.9
	 				"Low"
	 			when 4.0..6.9
	 				"Medium"
	 			when 7.0..8.9
	 				"High"
	 			when 9.0..10.0
	 				"Critical"
	 			else
	 				nil
	 			end
	 	end
	end
end