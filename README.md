# Cvss Rating

[![CircleCI](https://circleci.com/gh/mort666/cvss_rating.svg?style=svg)](https://circleci.com/gh/mort666/cvss_rating)

Implements vulnerability scoring system CVSS versions 2.0 and 3.0.

More information on the standard is available at [https://www.first.org/cvss](https://www.first.org/cvss)

## Installation

Add this line to your application's Gemfile:

    gem 'cvss_rating'

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install cvss_rating

## Usage

The following is basic usage to handle a CVSS 2.0 vector:

	cvs = Cvss2::Rating.new
	cvss.parse("AV:N/AC:M/Au:N/C:P/I:P/A:P")

	# Calculate overallscore
	cvss.overallscore

The following is basic usage to handle a CVSS 3.0 vector:

	cvss = Cvss3::Rating.new
	cvss.parse("AV:P/AC:H/PR:H/UI:R/S:C/C:H/I:L/A:N/E:U/RL:O/RC:U/CR:L/IR:L/AR:L")

	# Calculate Base Score (returns array of score and risk level)
	cvss.cvss_base_score

	# Calculate Temporal Score (returns array of score and risk level)
	cvss.cvss_temporal_score

	# Calculate Environmental Score (returns array of score and risk level)
	cvss.cvss_environmental_score

Check out the unit tests for more examples of usage.

## TODO

* Code and API clean up
* More Unit Tests

## License

Copyright (c) Stephen Kapp 2015.

Released under the MIT License
