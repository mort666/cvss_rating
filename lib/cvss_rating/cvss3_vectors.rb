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

	def mav=(mav)
		@mav = case mav
		when "physical", "P"
			::Cvss3::Metrics::ATTACK_VECTOR[:physical]
	    when "local", "L"
	    	::Cvss3::Metrics::ATTACK_VECTOR[:local]
	    when "adjacent network", "A"
	    	::Cvss3::Metrics::ATTACK_VECTOR[:adjacent_network]
	    when "network", "N"
	    	::Cvss3::Metrics::ATTACK_VECTOR[:network]
	    when "not_defined", "ND"
	    	nil
	    else 
	      raise "Bad Argument"
	    end
	end

	def mav
	    mav = get_key("ATTACK_VECTOR", @mav) if !@mav.nil?
	end

	def mac=(mac)
		@mac = case mac
		when "high", "H"
			::Cvss3::Metrics::ATTACK_COMPLEXITY[:high]
	    when "low", "L"
	    	::Cvss3::Metrics::ATTACK_COMPLEXITY[:low]
	    when "not_defined", "ND"
	    	nil
	    else 
	      raise "Bad Argument"
	    end
	end

	def mac
	    mac = get_key("ATTACK_COMPLEXITY", @mac) if !@mac.nil?
	end

	def mui=(mui)
		@mui = case mui
		when "none", "N"
			::Cvss3::Metrics::USER_INTERACTION[:none]
	    when "required", "R" 
	    	::Cvss3::Metrics::USER_INTERACTION[:required]
	    when "not_defined", "ND"
	    	nil
	    else 
	      raise "Bad Argument"
	    end
	end

	def mui
	    mui = get_key("USER_INTERACTION", @mui) if !@mui.nil?
	end

	def mpr=(mpr)
		@mpr = case mpr
		when "none", "N"
			::Cvss3::Metrics::PRIVILEGE_REQUIRED[:none]
	    when "low", "L" 
	    	::Cvss3::Metrics::PRIVILEGE_REQUIRED[:low]
	    when "high", "H" 
	     	::Cvss3::Metrics::PRIVILEGE_REQUIRED[:high]
	    when "not_defined", "ND"
	    	nil
	    else 
	      raise "Bad Argument" 
	    end
	end

	def mpr
		if @ms == "changed"
			mpr = get_key("PRIVILEGE_REQUIRED_CHANGED", @mpr) if !@mpr.nil?
	    else
	    	mpr = get_key("PRIVILEGE_REQUIRED", @mpr) if !@mpr.nil?
	    end
	end

	def ms=(ms)
		@ms = case ms
		when "changed", "C"
			"changed"
	    when "unchanged", "U"
	    	"unchanged"
	    when "not_defined", "ND"
	    	nil
	    else 
	      raise "Bad Argument"
	    end

	    if @ms == "changed"
	    	@mpr = case get_key("PRIVILEGE_REQUIRED", @mpr).nil? ? get_key("PRIVILEGE_REQUIRED_CHANGED", @mpr) : get_key("PRIVILEGE_REQUIRED", @mpr)
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
			self.mpr = get_key("PRIVILEGE_REQUIRED", @mpr).nil? ? get_key("PRIVILEGE_REQUIRED_CHANGED", @mpr) : get_key("PRIVILEGE_REQUIRED", @mpr)
		end
	end

	def ms
	    ms = ::Cvss3::Metrics::SCOPE_KEY[@ms.to_sym] if !@ms.nil?
	end	

	def mc=(mc)
		@mc = case mc
		when "none", "N"
			::Cvss3::Metrics::CIA_IMPACT[:none]
	    when "low", "L" 
	    	::Cvss3::Metrics::CIA_IMPACT[:low]
	   	when "high", "H" 
	    	::Cvss3::Metrics::CIA_IMPACT[:high]
	    when "not_defined", "ND"
	    	nil
	    else 
	      raise "Bad Argument"
	    end
	end

	def mc
	    mc = get_key("CIA_IMPACT", @mc) if !@mc.nil?
	end

	def mi=(mi)
		@mi = case mi
		when "none", "N"
			::Cvss3::Metrics::CIA_IMPACT[:none]
	    when "low", "L" 
	    	::Cvss3::Metrics::CIA_IMPACT[:low]
	   	when "high", "H" 
	    	::Cvss3::Metrics::CIA_IMPACT[:high]
	    when "not_defined", "ND"
	    	nil
	    else 
	      raise "Bad Argument"
	    end
	end

	def mi
	    mi = get_key("CIA_IMPACT", @mi) if !@mi.nil?
	end

	def ma=(ma)
		@ma = case ma
		when "none", "N"
			::Cvss3::Metrics::CIA_IMPACT[:none]
	    when "low", "L" 
	    	::Cvss3::Metrics::CIA_IMPACT[:low]
	   	when "high", "H" 
	    	::Cvss3::Metrics::CIA_IMPACT[:high]
	    when "not_defined", "ND"
	    	nil
	    else 
	      raise "Bad Argument"
	    end
	end

	def ma
	    am = get_key("CIA_IMPACT", @ma) if !@ma.nil?
	end

	def ex=(ex)
		@ex = case ex
		when "unproven", "U" then ::Cvss3::Metrics::EXPLOITABILITY[:unproven]
		when "proof-of-concept", "P", "POC" then ::Cvss3::Metrics::EXPLOITABILITY[:poc]
		when "functional", "F" then ::Cvss3::Metrics::EXPLOITABILITY[:functional]
		when "high", "H" then ::Cvss3::Metrics::EXPLOITABILITY[:high]      
		when "not defined", "ND" then ::Cvss3::Metrics::EXPLOITABILITY[:not_defined]
		else 
		  raise "Bad Argument"
		end
	end
	
	def ex
	  	ex = get_key("EXPLOITABILITY", @ex) if !@ex.nil?
	end
	
	def rl=(rl)
		@rl = case rl
		when "official-fix", "O" then ::Cvss3::Metrics::REMEDIATION_LEVEL[:official]
		when "temporary-fix", "T", "TF" then ::Cvss3::Metrics::REMEDIATION_LEVEL[:temporary]
		when "workaround", "W" then ::Cvss3::Metrics::REMEDIATION_LEVEL[:workaround]
		when "unavailable", "U" then ::Cvss3::Metrics::REMEDIATION_LEVEL[:unavailable]      
		when "not defined", "ND" then ::Cvss3::Metrics::REMEDIATION_LEVEL[:not_defined]
		else 
		  raise "Bad Argument"
		end
	end
	
	def rl
	  	rl = get_key("REMEDIATION_LEVEL", @rl) if !@rl.nil?
	end
	
	def rc=(rc)
		@rc = case rc
		when "unknown", "U" then ::Cvss3::Metrics::REPORT_CONFIDENCE[:unknown]
		when "reasonable", "R" then ::Cvss3::Metrics::REPORT_CONFIDENCE[:reasonable]
		when "confirmed", "C" then ::Cvss3::Metrics::REPORT_CONFIDENCE[:confirmed]    
		when "not defined", "ND" then ::Cvss3::Metrics::REPORT_CONFIDENCE[:not_defined]
		else 
		  raise "Bad Argument"
		end
	 end
	
	def rc
	  	rc = get_key("REPORT_CONFIDENCE", @rc) if !@av.nil?
	end	

	def cr=(cr)
	    @cr = case cr
	    when "low", "L" then ::Cvss3::Metrics::CIA_REQUIREMENT[:low]
	    when "medium", "M" then ::Cvss3::Metrics::CIA_REQUIREMENT[:medium]
	    when "high", "H" then ::Cvss3::Metrics::CIA_REQUIREMENT[:high]      
	    when "not defined", "ND" then ::Cvss3::Metrics::CIA_REQUIREMENT[:notdefined]
	    else 
	      raise "Bad Argument"
	    end
	end
	  
	def cr
	    cr = get_key("CIA_REQUIREMENT", @cr) if !@cr.nil?
	end
	  
	def ir=(ir)
	    @ir = case ir
	    when "low", "L" then ::Cvss3::Metrics::CIA_REQUIREMENT[:low]
	    when "medium", "M" then ::Cvss3::Metrics::CIA_REQUIREMENT[:medium]
	    when "high", "H" then ::Cvss3::Metrics::CIA_REQUIREMENT[:high]      
	    when "not defined", "ND" then ::Cvss3::Metrics::CIA_REQUIREMENT[:notdefined]
	    else 
	      raise "Bad Argument"
	    end
	end
	  
	def ir
	    ir = get_key("CIA_REQUIREMENT", @ir) if !@ir.nil?
	end
	  
	def ar=(ar)
	    @ar = case ar
	    when "low", "L" then ::Cvss3::Metrics::CIA_REQUIREMENT[:low]
	    when "medium", "M" then ::Cvss3::Metrics::CIA_REQUIREMENT[:medium]
	    when "high", "H" then ::Cvss3::Metrics::CIA_REQUIREMENT[:high]      
	    when "not defined", "ND" then ::Cvss3::Metrics::CIA_REQUIREMENT[:notdefined]
	    else 
	      raise "Bad Argument"
	    end
	end
	  
	def ar
	    ar = get_key("CIA_REQUIREMENT", @ar) if !@ar.nil?
	end


	def init(ex = "ND", rl = "ND", rc = "ND", cd = "ND", td = "ND", cr = "ND", ir = "ND", ar = "ND", 
			mav = "ND", mac = "ND", mpv = "ND", mui = "ND", mc = "ND", mi = "ND", ma = "ND")
	    self.ex = ex
	    self.rl = rl
	    self.rc = rc

		self.cr = cr
		self.ir = ir
	    self.ar = ar

	    self.mav = mav
	    self.mac = mac
	    self.mpr = mpv
	    self.mui = mui

	    self.mc = mc
	    self.mi = mi
	    self.ma = ma	
	end

end