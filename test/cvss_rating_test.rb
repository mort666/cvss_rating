require 'minitest/autorun'
require 'active_support'
require 'cvss_rating'

class CvssRatingTest < MiniTest::Unit::TestCase
	def setup
		@cvss = Cvss2::Rating.new
		@cvss.av = "N"
		@cvss.ac = "M"
		@cvss.au = "N"
		@cvss.ci = "P"
		@cvss.ii = "P"
		@cvss.ai = "P"
		@cvss.set_key

		@cvss_2 = Cvss2::Rating.new
		@cvss_2.av = "L"
		@cvss_2.ac = "M"
		@cvss_2.au = "M"
		@cvss_2.ci = "P"
		@cvss_2.ii = "C"
		@cvss_2.ai = "C"
		@cvss_2.cdp = "L"
		@cvss_2.td = "H"
		@cvss_2.cr = "M"
		@cvss_2.ir = "M"
		@cvss_2.ar = "M"
		@cvss_2.set_key
	end

	def test_cvss_rating_from_vector
		cvss = Cvss2::Rating.new
		cvss.parse("AV:N/AC:M/Au:N/C:P/I:P/A:P")
		assert_equal @cvss.key, cvss.key

		assert_equal @cvss.base, cvss.base

		assert_equal @cvss.overallscore, cvss.overallscore

		cvss.parse("AV:L/AC:M/Au:M/C:P/I:C/A:C/CDP:L/TD:H/CR:M/IR:M/AR:M")
		assert_equal @cvss_2.key, cvss.key

		assert_equal @cvss_2.base, cvss.base

		assert_equal @cvss_2.overallscore, cvss.overallscore
	end

	def test_cvss_rating_parameters
		cvss = Cvss2::Rating.new

		cvss.av = "local"

		assert_equal @cvss_2.av, cvss.av

		cvss.cdp = 'low'

		assert_equal @cvss_2.cdp, cvss.cdp
	end

	def test_cvss_rating_scores
		cvss = Cvss2::Rating.new

		cvss.scores("N", "M", "N", "P", "P", "P")
		assert_equal @cvss.key, cvss.key

		cvss.scores("L", "M", "M", "P", "C", "C", "ND", "ND", "ND", "L", "H",  "M", "M",  "M")
		assert_equal @cvss_2.key, cvss.key
	end
end