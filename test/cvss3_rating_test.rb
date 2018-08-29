require 'minitest/autorun'
require 'active_support'
require 'cvss3_rating'
require 'byebug'

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

	def test_valid_vector
		cvss = Cvss3::Rating.new

		err = assert_raises RuntimeError do
			cvss.parse("AV:P/AC:H/PR:L/UI:R/S:U/C:H/I:X/A:N")
		end

		assert_match /Bad Argument/, err.message

		err = assert_raises RuntimeError do
			cvss.parse("CVSS:9.9/AV:P/AC:H/PR:L/UI:R/S:U/C:H/I:L/A:N")
		end

		assert_match /Bad CVSS 3.0 Vector String/, err.message
	end

	def test_cvss_rating_parameters
		cvss = Cvss3::Rating.new

		cvss.av = "physical"

		assert_equal @cvss.av, cvss.av

		# cvss.pr = 'low'
    #
		# assert_equal @cvss.pr, cvss.pr

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

	def test_base_score
		cvss = Cvss3::Rating.new
		cvss.parse("AV:P/AC:H/PR:L/UI:R/S:U/C:H/I:N/A:N")

		score = cvss.cvss_base_score

		assert_equal 3.9, score[0]

		assert_equal "Low", score[1]

		cvss = Cvss3::Rating.new
		cvss.parse("AV:P/AC:H/PR:H/UI:R/S:C/C:H/I:L/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L")

		score = cvss.cvss_base_score

		assert_equal 5.4, score[0]

		assert_equal "Medium", score[1]

	end

	def test_temporal_score
		cvss = Cvss3::Rating.new
		cvss.parse("AV:P/AC:H/PR:L/UI:R/S:U/C:H/I:N/A:N")

		cvss.cvss_base_score

		score = cvss.cvss_temporal_score

		assert_equal 3.9, score[0]

		assert_equal "Low", score[1]

		cvss = Cvss3::Rating.new
		cvss.parse("AV:P/AC:H/PR:H/UI:R/S:C/C:H/I:L/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L")

		cvss.cvss_base_score

		score = cvss.cvss_temporal_score

		assert_equal 4.3, score[0]

		assert_equal "Medium", score[1]
	end

	def test_environmental_score
		cvss = Cvss3::Rating.new
		cvss.parse("AV:P/AC:H/PR:L/UI:R/S:U/C:H/I:N/A:N")

		cvss.cvss_base_score

		score = cvss.cvss_environmental_score

		assert_equal 3.9, score[0]

		assert_equal "Low", score[1]

		cvss = Cvss3::Rating.new
		cvss.parse("AV:P/AC:H/PR:H/UI:R/S:C/C:H/I:L/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L")

		cvss.cvss_base_score

		score = cvss.cvss_environmental_score

		assert_equal 2.4, score[0]

		assert_equal "Low", score[1]

		cvss = Cvss3::Rating.new
		cvss.parse("AV:P/AC:H/PR:H/UI:R/S:C/C:H/I:L/A:N/E:U/RL:O/RC:U/IR:L/AR:L/MAV:A/MPR:N")

		cvss.cvss_base_score

		score = cvss.cvss_environmental_score

		assert_equal 4.8, score[0]

		assert_equal "Medium", score[1]

		cvss = Cvss3::Rating.new
		cvss.parse("CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:C/C:H/I:L/A:N/E:U/RL:O/RC:U/MAV:N/MS:U")

		cvss.cvss_base_score

		score = cvss.cvss_environmental_score

		assert_equal 3.9, score[0]

		assert_equal "Low", score[1]
	end

	def test_parsing
		cvss = Cvss3::Rating.new
		cvss.parse('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H')

		score = cvss.cvss_base_score

		assert_equal 10, score[0]

		assert_equal "Critical", score[1]

		assert_equal "H", cvss.ex

		assert_equal "N", cvss.ui

		assert_equal "U", cvss.rl


		cvss = Cvss3::Rating.new
		cvss.parse('AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H')

		score = cvss.cvss_base_score

		assert_equal 9.1, score[0]

		assert_equal "Critical", score[1]

		assert_equal "H", cvss.pr
	end


	def test_all_scores
		cvss = Cvss3::Rating.new
		cvss.parse("AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N/E:X/RL:X/RC:X")

		score = cvss.cvss_base_score

		assert_equal 0.0, score[0]

		score = cvss.cvss_temporal_score

		assert_equal 0.0, score[0]

		score = cvss.cvss_environmental_score

		assert_equal 0.0, score[0]

		cvss.parse("AV:L/AC:L/PR:H/UI:R/S:U/C:H/I:N/A:H/E:H/RL:W/RC:U/CR:H/IR:H/AR:M/MAV:L/MAC:L/MPR:H/MUI:N/MS:C/MC:N/MI:H/MA:L")

		score = cvss.cvss_base_score

		assert_equal 5.8, score[0]

		score = cvss.cvss_temporal_score

		assert_equal 5.2, score[0]

		score = cvss.cvss_environmental_score

		assert_equal 7.4, score[0]
	end

end
