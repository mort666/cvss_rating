module Cvss3Vectors
	attr_reader :av, :ac, :ui, :sc, :ci, :ai, :ii, :ex, :rl, :rc, :pr, :td, :cr, :ir

	VECTORS = {
	    "av" => "av=",
	    "ac" => "ac=",
	    "ui" => "ui=",
	    "s" => "sc=",
	    "c" => "ci=",
	    "i" => "ii=",
	    "a" => "ai=",
	    "e" => "ex=",
	    "rl" => "rl=",
	    "rc" => "rc=",
	    "pr" => "pr=",
	    "td" => "td=",
	    "cr" => "cr=",
	    "ir" => "ir=",
	    "mav" => "mav=",
	    "mac" => "mac=",
	    "ms" => "ms=",
	    "mpr" => "mpr=",
	    "mui" => "mui=",
	    "mc" => "mc=",
	    "mi" => "mi=",
	    "ma" => "ma="
	}

	def parse(vector)
		string = vector.split("/")
	    len = string.length

	    init

	    @originalkey = vector
	    
	    string.each do |section|
	      tmp = section.split(":")
	      send(VECTORS[tmp[0].downcase].to_sym, tmp[1])     
	    end
	end

	def get_key(vector, value)
		get_key = eval("::Cvss3::Metrics::" + vector + "_KEY")[(eval("::Cvss3::Metrics::" + vector).select { |k,v| v == value }).keys[0]]
	end

	def av=(av)
		@av = case av
		when "physical", "P"
			::Cvss3::Metrics::ATTACK_VECTOR[:physical]
	    when "local", "L"
	    	::Cvss3::Metrics::ATTACK_VECTOR[:local]
	    when "adjacent network", "A"
	    	::Cvss3::Metrics::ATTACK_VECTOR[:adjacent_network]
	    when "network", "N"
	    	::Cvss3::Metrics::ATTACK_VECTOR[:network]
	    else 
	      raise "Bad Argument"
	    end
	end

	def av
	    av = get_key("ATTACK_VECTOR", @av) if !@av.nil?
	end

	def ac=(ac)
		@ac = case ac
		when "high", "H"
			::Cvss3::Metrics::ATTACK_COMPLEXITY[:high]
	    when "low", "L"
	    	::Cvss3::Metrics::ATTACK_COMPLEXITY[:low]
	    else 
	      raise "Bad Argument"
	    end
	end

	def ac
	    ac = get_key("ATTACK_COMPLEXITY", @ac) if !@ac.nil?
	end

	def ui=(ui)
		@ui = case ui
		when "none", "N"
			::Cvss3::Metrics::USER_INTERACTION[:none]
	    when "required", "R" 
	    	::Cvss3::Metrics::USER_INTERACTION[:required]
	    else 
	      raise "Bad Argument"
	    end
	end

	def ui
	    ui = get_key("USER_INTERACTION", @ui) if !@ui.nil?
	end

	def pr=(pr)
		@pr = case pr
		when "none", "N"
			::Cvss3::Metrics::PRIVILEGE_REQUIRED[:none]
	    when "low", "L" 
	    	::Cvss3::Metrics::PRIVILEGE_REQUIRED[:low]
	    when "high", "H" 
	     	::Cvss3::Metrics::PRIVILEGE_REQUIRED[:high]
	    else 
	      raise "Bad Argument" 
	    end
	end

	def pr
		if @sc == "changed"
			pr = get_key("PRIVILEGE_REQUIRED_CHANGED", @pr) if !@pr.nil?
	    else
	    	pr = get_key("PRIVILEGE_REQUIRED", @pr) if !@pr.nil?
	    end
	end

	def sc=(sc)
		@sc = case sc
		when "changed", "C"
			"changed"
	    when "unchanged", "U"
	    	"unchanged"
	    else 
	      raise "Bad Argument"
	    end

	    if @sc == "changed"
	    	@pr = case get_key("PRIVILEGE_REQUIRED", @pr).nil? ? get_key("PRIVILEGE_REQUIRED_CHANGED", @pr) : get_key("PRIVILEGE_REQUIRED", @pr)
			when "none", "N",
				::Cvss3::Metrics::PRIVILEGE_REQUIRED_CHANGED[:none]
		    when "low", "L"
		     	::Cvss3::Metrics::PRIVILEGE_REQUIRED_CHANGED[:low]
		    when "high", "H" 
		    	::Cvss3::Metrics::PRIVILEGE_REQUIRED_CHANGED[:high]
		    else 
		      raise "Bad Argument"
		    end
		else
			self.pr = get_key("PRIVILEGE_REQUIRED", @pr).nil? ? get_key("PRIVILEGE_REQUIRED_CHANGED", @pr) : get_key("PRIVILEGE_REQUIRED", @pr)
		end
	end

	def sc
	    sc = ::Cvss3::Metrics::SCOPE_KEY[@sc.to_sym] if !@sc.nil?
	end	

	def ci=(ci)
		@ci = case ci
		when "none", "N"
			::Cvss3::Metrics::CIA_IMPACT[:none]
	    when "low", "L" 
	    	::Cvss3::Metrics::CIA_IMPACT[:low]
	   	when "high", "H" 
	    	::Cvss3::Metrics::CIA_IMPACT[:high]
	    else 
	      raise "Bad Argument"
	    end
	end

	def ci
	    ci = get_key("CIA_IMPACT", @ci) if !@ci.nil?
	end

	def ii=(ii)
		@ii = case ii
		when "none", "N"
			::Cvss3::Metrics::CIA_IMPACT[:none]
	    when "low", "L" 
	    	::Cvss3::Metrics::CIA_IMPACT[:low]
	   	when "high", "H" 
	    	::Cvss3::Metrics::CIA_IMPACT[:high]
	    else 
	      raise "Bad Argument"
	    end
	end

	def ii
	    ii = get_key("CIA_IMPACT", @ii) if !@ii.nil?
	end

	def ai=(ai)
		@ai = case ai
		when "none", "N"
			::Cvss3::Metrics::CIA_IMPACT[:none]
	    when "low", "L" 
	    	::Cvss3::Metrics::CIA_IMPACT[:low]
	   	when "high", "H" 
	    	::Cvss3::Metrics::CIA_IMPACT[:high]
	    else 
	      raise "Bad Argument"
	    end
	end

	def ai
	    ai = get_key("CIA_IMPACT", @ai) if !@ai.nil?
	end

end