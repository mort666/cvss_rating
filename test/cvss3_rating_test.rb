require 'minitest/autorun'
require 'active_support'
require 'cvss3_rating'

class Cvss3RatingTest < MiniTest::Test
	def setup
		@cvss = Cvss3::Rating.new
		@cvss.av = "P"
		@cvss.ac = "H"
		@cvss.ui = "R"
		@cvss.pr = "L"
		@cvss.sc = "C"
		@cvss.ci = "H"
		@cvss.ii = "low"
		@cvss.ai = "N"

		@cvss_2 = Cvss3::Rating.new
		@cvss_2.av = "P"
		@cvss_2.ac = "H"
		@cvss_2.ui = "R"
		@cvss_2.pr = "H"
		@cvss_2.sc = "C"
		@cvss_2.ci = "H"
		@cvss_2.ii = "low"
		@cvss_2.ai = "N"
		@cvss_2.ex = "U"
		@cvss_2.rl = "O"
		@cvss_2.rc = "U"
		@cvss_2.cr = "L"
		@cvss_2.ir = "L"
		@cvss_2.ar = "L"
	end

	def test_cvss_rating_from_vector
		cvss = Cvss3::Rating.new
		cvss.parse("AV:P/AC:H/PR:L/UI:R/S:C/C:H/I:L/A:N")

		assert_equal @cvss.ai, cvss.ai

		assert_equal @cvss.ii, cvss.ii

		assert_equal @cvss.av, cvss.av

		assert_equal @cvss.ui, cvss.ui

		assert_equal @cvss.key, cvss.key

		cvss = Cvss3::Rating.new
		cvss.parse("AV:P/AC:H/PR:H/UI:R/S:C/C:H/I:L/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L")

		assert_equal @cvss_2.ai, cvss.ai

		assert_equal @cvss_2.ii, cvss.ii

		assert_equal @cvss_2.av, cvss.av

		assert_equal @cvss_2.key, cvss.key
	end

	def test_cvss_rating_parameters
		cvss = Cvss3::Rating.new

		cvss.av = "physical"

		assert_equal @cvss.av, cvss.av

		cvss.pr = 'low'

		assert_equal @cvss.pr, cvss.pr

		cvss.ci = 'high'

		assert_equal @cvss.ci, cvss.ci

		cvss.ai = 'none'

		assert_equal @cvss.ai, cvss.ai

	end

	def test_cvss_risk_rating
		cvss = Cvss3::Rating.new

		assert_equal "None", cvss.risk_score(0.0)

		assert_equal "Low", cvss.risk_score(2.0)
		
		assert_equal "Medium", cvss.risk_score(5.1)
		
		assert_equal "High", cvss.risk_score(7.1)
		
		assert_equal "Critical", cvss.risk_score(10.0)
		
		assert_equal nil, cvss.risk_score(11.0)
	end
end