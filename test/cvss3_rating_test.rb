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
	end

	def test_cvss_rating_from_vector
		cvss = Cvss3::Rating.new
		cvss.parse("AV:P/AC:H/PR:L/UI:R/S:C/C:H/I:L/A:N")
		assert_equal @cvss.ai, cvss.ai

		assert_equal @cvss.ii, cvss.ii

		assert_equal @cvss.av, cvss.av

		assert_equal @cvss.ui, cvss.ui
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
end