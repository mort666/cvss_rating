# @author Stephen Kapp

require "cvss_rating/version"
require "cvss_rating/cvss3_formulas"
require "cvss_rating/cvss3_metrics"
require "cvss_rating/cvss3_vectors"

module Cvss3
	class Rating
		attr_accessor :exploitability, :base, :impact, :temporal, :environmental

		include Cvss3Vectors

		#
		# Initialize the object, creates a clean initialized Cvss3::Rating object
		#
		# @param list [Hash] list of CVSS 3.0 attributes to be used during initialization
		#

		def initialize(attributes = {})   
			init

	    	attributes.each do |name, value|
	      		send("#{name}=", value)
	    	end
	 	end

	 	
	 	#
	 	# Takes score and determines risk level from None to Critical
	 	#
	 	# @param score [Float] risk score to be converted to risk level
	 	# @return [String] risk level based on score

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

	 
	 	#
	 	# Calculate the CVSS 3.0 Base Score
	 	#
	 	# @return [Array] the CVSS 3.0 Base score with its risk level

	 	def cvss_base_score
	 		@exploitability = ::Cvss3::Formulas.new.exploitability_sub_score(@av, @ac, @pr, @ui)

			@impact = ::Cvss3::Formulas.new.impact_sub_score_base(@ai, @ci, @ii)	 	

			@base = ::Cvss3::Formulas.new.cvss_base_formula(@impact, @sc, @exploitability)

			@base_level = risk_score(@base)	

			return @base, @base_level
	 	end

	 	##
	 	#
	 	# Calculate the CVSS 3.0 Temporal Score
	 	#
	 	# @return [Array] the CVSS 3.0 Temporal score with its risk level

	 	def cvss_temporal_score
	 		@temporal = ::Cvss3::Formulas.new.cvss_temporal_formula(@base, @ex, @rl, @rc)

	 		@temporal_level = risk_score(@temporal)

	 		return @temporal, @temporal_level
	 	end

	 	##
	 	#
	 	# Calculate the CVSS 3.0 Temporal Score
	 	#
	 	# @return [Array] the CVSS 3.0 Temporal score with its risk level

	 	def cvss_environmental_score
	 		exploitability_sub_score_value_modified = ::Cvss3::Formulas.new.exploitability_sub_score_modified(self.mav(true), 
	 			self.mac(true), self.mpr(true), self.mui(true))

	 		impact_sub_score_value_modified = ::Cvss3::Formulas.new.impact_sub_score_modified_base(self.ma(true), self.mc(true), 
	 			self.mi(true), @cr, @ir, @ar)

	 		@environmental = ::Cvss3::Formulas.new.cvss_environmental_formula(impact_sub_score_value_modified, 
	 			exploitability_sub_score_value_modified,
	 			@ex, @rl, @rc, self.ms(true))

	 		@environmental_level = risk_score(@environmental)

	 		return @environmental, @environmental_level
	 	end
	end
end