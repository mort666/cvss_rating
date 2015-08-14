require "cvss_rating/version"

module Cvss
	class Rating
  
	  attr_accessor :av, :ac, :au, :ci, :ii, :ai, :ex, :rl, :rc, :cdp, :td, :cr, :ir, :ar 
	  attr_accessor :base, :temporal, :overall, :environmental, :impact, :exploitability, :adjimpact, :key
	  
	  ACCESS_VECTOR = { :local => 0.395, :adjacent_network => 0.646, :network => 1.0 }
	  ACCESS_COMPLEXITY = { :high => 0.35, :medium => 0.61, :low => 0.71 }
	  AUTHENTICATION = { :none => 0.704, :single => 0.56, :multiple => 0.45 }
	  
	  CONFIDENTIALITY_IMPACT = { :none => 0.0, :partial => 0.275, :complete => 0.660 }
	  INTEGRITY_IMPACT = { :none => 0.0, :partial => 0.275, :complete => 0.660 }
	  AVAILABILITY_IMPACT = { :none => 0.0, :partial => 0.275, :complete => 0.660 }
	  
	  CONFIDENTIALITY_REQUIREMENT = { :low => 0.5, :medium => 1.0, :high => 1.51, :notdefined => -1.0 }
	  INTEGRITY_REQUIREMENT = { :low => 0.5, :medium => 1.0, :high => 1.51, :notdefined => -1.0 }
	  AVAILABILITY_REQUIREMENT = { :low => 0.5, :medium => 1.0, :high => 1.51, :notdefined => -1.0 }
	  
	  EXPLOITABILITY = { :unproven => 0.85, :poc => 0.9, :functional =>  0.95, :high => 1.0, :notdefined => -1.0 }
	  REMEDIATION_LEVEL = { :official => 0.87, :temporary => 0.9, :workaround =>  0.95, :unavailable => 1.0, :notdefined => -1.0 }
	  REPORT_CONFIDENCE = { :unconfirmed => 0.90, :uncorroborated => 0.95, :confirmed => 1.0, :notdefined => -1.0 }
	  
	  COLLATERAL_DAMAGE = { :none => 0.0, :low => 0.1, :low_medium => 0.3, :medium_high => 0.4, :high => 0.5, :notdefined => -1.0 }
	  TARGET_DISTRIBUTION = { :none => 0.0, :low => 0.25, :medium => 0.75, :high => 1.0, :notdefined => -1.0 }
	  
	  ACCESS_VECTOR_KEY = { :local => 'L', :adjacent_network => 'A', :network => 'N' }
	  ACCESS_COMPLEXITY_KEY = { :high => 'H', :medium => 'M', :low => 'L' }
	  AUTHENTICATION_KEY = { :none => 'N', :single => 'S', :multiple => 'M' }
	  
	  CONFIDENTIALITY_IMPACT_KEY = { :none => 'N', :partial => 'P', :complete => 'C' }
	  INTEGRITY_IMPACT_KEY = { :none => 'N', :partial => 'P', :complete => 'C' }
	  AVAILABILITY_IMPACT_KEY = { :none => 'N', :partial => 'P', :complete => 'C' }
	  
	  CONFIDENTIALITY_REQUIREMENT_KEY = { :low => 'L', :medium => 'M', :high => 'H', :notdefined => 'ND' }
	  INTEGRITY_REQUIREMENT_KEY = { :low => 'L', :medium => 'M', :high => 'H', :notdefined => 'ND' }
	  AVAILABILITY_REQUIREMENT_KEY = { :low => 'L', :medium => 'M', :high => 'H', :notdefined => 'ND' }
	  
	  EXPLOITABILITY_KEY = { :unproven => 'U', :poc => 'P', :functional => 'F', :high => 'H', :notdefined => 'ND' }
	  REMEDIATION_LEVEL_KEY = { :official => 'OF', :temporary => "TF", :workaround =>  'W', :unavailable => 'U', :notdefined => 'ND' }
	  REPORT_CONFIDENCE_KEY = { :unconfirmed => 'UC', :uncorroborated => 'UR', :confirmed => 'C', :notdefined => 'ND' }
	  
	  COLLATERAL_DAMAGE_KEY = { :none => 'N', :low => 'L', :low_medium => 'LM', :medium_high => 'MH', :high => 'H', :notdefined => 'ND' }
	  TARGET_DISTRIBUTION_KEY = { :none => 'N', :low => 'L', :medium => 'M', :high => 'H', :notdefined => 'ND' }	  

	  def initialize(attributes = {})   
	    @base = nil 
	    @temporal = nil 
	    @environmental = nil 
	    
	    self.init

	    attributes.each do |name, value|
	      send("#{name}=", value)
	    end
	  end
	  
	  def init(ex = "ND", rl = "ND", rc = "ND", cd = "ND", td = "ND", cr = "ND", ir = "ND", ar = "ND")
	    self.ex = ex
	    self.rl = rl
	    self.rc = rc

	    self.cdp = cd
		self.td = td
		self.cr = cr
		self.ir = ir
	    self.ar = ar
	  end
	  
	  def scores(av, ac, au, ci, ii, ai, ex = "ND", rl = "ND", rc = "ND", cd = "ND", td = "ND", cr = "ND", ir = "ND", ar = "ND")
	    self.av = av
	    self.ac = ac
	    self.au = au
	    self.ci = ci
	    self.ii = ii
	    self.ai = ai
	    
	    self.ex = ex
	    self.rl = rl
	    self.rc = rc

	    self.cd = cd
		self.td = td
		self.cr = cr
		self.ir = ir
	    self.ar = ar
	  end
	  
	  def get_key(vector, value)
	    get_key = eval(vector + "_KEY")[(eval(vector).select { |k,v| v == value }).keys[0]]
	  end
	  
	  def noenvironmental
	    if get_key("COLLATERAL_DAMAGE", @cdp) == "ND" && get_key("TARGET_DISTRIBUTION", @td) == "ND" && get_key("CONFIDENTIALITY_REQUIREMENT", @cr) == "ND" && get_key("INTEGRITY_REQUIREMENT", @ir) == "ND" && get_key("AVAILABILITY_REQUIREMENT", @ar) == "ND"
	      return true
	    else
	      return false
	    end
	  end
	  
	  def notemporal
	    if get_key("EXPLOITABILITY", @ex) == "ND" && get_key("REMEDIATION_LEVEL", @rl) == "ND" && get_key("REPORT_CONFIDENCE", @rc) == "ND"
	      return true
	    else
	      return false
	    end
	  end
	  
	  def set_key
	    @key = "AV:%s/AC:%s/Au:%s/C:%s/I:%s/A:%s" % [ get_key("ACCESS_VECTOR", @av),
	        get_key("ACCESS_COMPLEXITY", @ac),
	        get_key("AUTHENTICATION", @au),
	        get_key("CONFIDENTIALITY_IMPACT", @ci),
	        get_key("INTEGRITY_IMPACT", @ii),
	        get_key("AVAILABILITY_IMPACT", @ai)]
	        
	    if !notemporal
	      @key += "/E:%s/RL:%s/RC:%s" % [ get_key("EXPLOITABILITY", @ex),
	          get_key("REMEDIATION_LEVEL", @rl),
	          get_key("REPORT_CONFIDENCE", @rc)]
	    end
	    
	    if !noenvironmental
	      @key += "/CDP:%s/TD:%s/CR:%s/IR:%s/AR:%s" % [ get_key("COLLATERAL_DAMAGE", @cdp),
	          get_key("TARGET_DISTRIBUTION", @td),
	          get_key("CONFIDENTIALITY_REQUIREMENT", @cr),
	          get_key("INTEGRITY_REQUIREMENT", @ir),
	          get_key("AVAILABILITY_REQUIREMENT", @ar)]
	    end
	  end
	  
	  def av=(av)
	    @av = case av
	    when "local", "L" then ACCESS_VECTOR[:local]
	    when "adjacent network", "A" then ACCESS_VECTOR[:adjacent_network]
	    when "network", "N" then ACCESS_VECTOR[:network]
	    else 
	      raise "Bad Argument"
	    end
	  end
	  
	  def av
	    av = get_key("ACCESS_VECTOR", @av) if !@av.nil?
	  end
	  
	  def ac=(ac)
	    @ac = case ac
	    when "high", "H" then ACCESS_COMPLEXITY[:high]
	    when "medium", "M" then ACCESS_COMPLEXITY[:medium]
	    when "low", "L" then ACCESS_COMPLEXITY[:low]
	    else 
	      raise "Bad Argument"
	    end
	  end
	  
	  def ac
	    ac = get_key("ACCESS_COMPLEXITY", @ac) if !@ac.nil?
	  end
	  
	  def au=(au)
	    @au = case au
	    when "none", "N" then AUTHENTICATION[:none]
	    when "single instance", "S" then AUTHENTICATION[:single]
	    when "multiple instance", "M" then AUTHENTICATION[:multiple]
	    else 
	      raise "Bad Argument"
	    end
	  end
	  
	  def au
	    au = get_key("AUTHENTICATION", @au) if !@au.nil?
	  end
	  
	  def ci=(ci)
	    @ci = case ci
	    when "none", "N" then CONFIDENTIALITY_IMPACT[:none]
	    when "partial", "P" then CONFIDENTIALITY_IMPACT[:partial]
	    when "complete", "C" then CONFIDENTIALITY_IMPACT[:complete]
	    else 
	      raise "Bad Argument"
	    end
	  end
	  
	  def ci
	    ci = get_key("CONFIDENTIALITY_IMPACT", @ci) if !@ci.nil?
	  end
	  
	  def ii=(ii)
	    @ii = case ii
	    when "none", "N" then INTEGRITY_IMPACT[:none]
	    when "partial", "P" then INTEGRITY_IMPACT[:partial]
	    when "complete", "C" then INTEGRITY_IMPACT[:complete]
	    else 
	      raise "Bad Argument"
	    end
	  end
	  
	  def ii
	    ii = get_key("INTEGRITY_IMPACT", @ii) if !@ii.nil?
	  end
	  
	  def ai=(ai)
	    @ai = case ai
	    when "none", "N" then AVAILABILITY_IMPACT[:none]
	    when "partial", "P" then AVAILABILITY_IMPACT[:partial]
	    when "complete", "C" then AVAILABILITY_IMPACT[:complete]
	    else 
	      raise "Bad Argument"
	    end
	  end
	  
	  def ai
	    ai = get_key("AVAILABILITY_IMPACT", @ai) if !@ai.nil?
	  end
	  
	  def ex=(ex)
	    @ex = case ex
	    when "unproven", "U" then EXPLOITABILITY[:unproven]
	    when "proof-of-concept", "P", "POC" then EXPLOITABILITY[:poc]
	    when "functional", "F" then EXPLOITABILITY[:functional]
	    when "high", "H" then EXPLOITABILITY[:high]      
	    when "not defined", "ND" then EXPLOITABILITY[:notdefined]
	    else 
	      raise "Bad Argument"
	    end
	  end
	  
	  def ex
	    ex = get_key("EXPLOITABILITY", @ex) if !@ex.nil?
	  end
	  
	  def rl=(rl)
	    @rl = case rl
	    when "official-fix", "O" then REMEDIATION_LEVEL[:official]
	    when "temporary-fix", "T", "TF" then REMEDIATION_LEVEL[:temporary]
	    when "workaround", "W" then REMEDIATION_LEVEL[:workaround]
	    when "unavailable", "U" then REMEDIATION_LEVEL[:unavailable]      
	    when "not defined", "ND" then REMEDIATION_LEVEL[:notdefined]
	    else 
	      raise "Bad Argument"
	    end
	  end
	  
	  def rl
	    rl = get_key("REMEDIATION_LEVEL", @rl) if !@rl.nil?
	  end
	  
	  def rc=(rc)
	    @rc = case rc
	    when "unconfirmed", "UC" then REPORT_CONFIDENCE[:unconfirmed]
	    when "uncorroborated", "UR" then REPORT_CONFIDENCE[:uncorroborated]
	    when "confirmed", "C" then REPORT_CONFIDENCE[:confirmed]    
	    when "not defined", "ND" then REPORT_CONFIDENCE[:notdefined]
	    else 
	      raise "Bad Argument"
	    end
	   end
	  
	  def rc
	    rc = get_key("REPORT_CONFIDENCE", @rc) if !@av.nil?
	  end
	  
	  def cdp=(cd)
	    @cdp = case cd
	    when "none", "N" then COLLATERAL_DAMAGE[:none]
	    when "low", "L" then COLLATERAL_DAMAGE[:low]
	    when "low-medium", "LM" then COLLATERAL_DAMAGE[:low_medium]
	    when "medium-high", "MH" then COLLATERAL_DAMAGE[:medium_high]
	    when "high", "H" then COLLATERAL_DAMAGE[:high]      
	    when "not defined", "ND" then COLLATERAL_DAMAGE[:notdefined]
	    else 
	      raise "Bad Argument"
	    end
	  end
	  
	  def cdp
	    cdp = get_key("COLLATERAL_DAMAGE", @cdp) if !@cdp.nil?
	  end
	  
	  def td=(td)
	    @td = case td
	    when "none", "N" then TARGET_DISTRIBUTION[:none]
	    when "low", "L" then TARGET_DISTRIBUTION[:low]
	    when "medium", "M" then TARGET_DISTRIBUTION[:medium]
	    when "high", "H" then TARGET_DISTRIBUTION[:high]      
	    when "not defined", "ND" then TARGET_DISTRIBUTION[:notdefined]
	    else 
	      raise "Bad Argument"
	    end
	  end
	  
	  def td
	    td = get_key("TARGET_DISTRIBUTION", @td) if !@td.nil?
	  end
	  
	  def cr=(cr)
	    @cr = case cr
	    when "low", "L" then CONFIDENTIALITY_REQUIREMENT[:low]
	    when "medium", "M" then CONFIDENTIALITY_REQUIREMENT[:medium]
	    when "high", "H" then CONFIDENTIALITY_REQUIREMENT[:high]      
	    when "not defined", "ND" then CONFIDENTIALITY_REQUIREMENT[:notdefined]
	    else 
	      raise "Bad Argument"
	    end
	  end
	  
	  def cr
	    cr = get_key("CONFIDENTIALITY_REQUIREMENT", @cr) if !@cr.nil?
	  end
	  
	  def ir=(ir)
	    @ir = case ir
	    when "low", "L" then INTEGRITY_REQUIREMENT[:low]
	    when "medium", "M" then INTEGRITY_REQUIREMENT[:medium]
	    when "high", "H" then INTEGRITY_REQUIREMENT[:high]      
	    when "not defined", "ND" then INTEGRITY_REQUIREMENT[:notdefined]
	    else 
	      raise "Bad Argument"
	    end
	  end
	  
	  def ir
	    ir = get_key("INTEGRITY_REQUIREMENT", @ir) if !@ir.nil?
	  end
	  
	  def ar=(ar)
	    @ar = case ar
	    when "low", "L" then AVAILABILITY_REQUIREMENT[:low]
	    when "medium", "M" then AVAILABILITY_REQUIREMENT[:medium]
	    when "high", "H" then AVAILABILITY_REQUIREMENT[:high]      
	    when "not defined", "ND" then AVAILABILITY_REQUIREMENT[:notdefined]
	    else 
	      raise "Bad Argument"
	    end
	  end
	  
	  def ar
	    ar = get_key("AVAILABILITY_REQUIREMENT", @ar) if !@ar.nil?
	  end
	  
	  VECTORS = {
	    "av" => "av=",
	    "ac" => "ac=",
	    "au" => "au=",
	    "c" => "ci=",
	    "i" => "ii=",
	    "a" => "ai=",
	    "e" => "ex=",
	    "rl" => "rl=",
	    "rc" => "rc=",
	    "cdp" => "cdp=",
	    "td" => "td=",
	    "cr" => "cr=",
	    "ir" => "ir=",
	    "ar" => "ar="
	  }
	  
	  def parse(vector)
	    string = vector.split("/")
	    len = string.length

	    self.init

	    @originalkey = vector
	    
	    string.each do |section|
	      tmp = section.split(":")
	      send(VECTORS[tmp[0].downcase].to_sym, tmp[1])     
	    end
	  end  

	  def key
	  	self.set_key
	  	return @key
	  end

	  def to_s
	    printf "Base Score:\t\t\t%3.1f\n", @base
	    printf "  Impact Subscore:\t\t%3.1f\n", @impact
	    printf "  Exploitability Subscore:\t%3.1f\n", @exploitability
	    printf "Temporal Score:\t\t\t%3.1f\n", @temporal if !self.notemporal
	    printf "Environmental Score:\t\t%3.1f\n", @environmental  if !self.noenvironmental
	    printf "  Adjusted Impact Score:\t%3.1f\n", @adjimpact if !self.noenvironmental
	    printf "Overall Score:\t\t\t%3.1f\n", overallscore
	  end
	  
	  def calculate
	    @impact = self.impactscore
	    @adjimpact = self.adjustedimpactscore
	    @exploitability = self.exploitabilityscore
	    @base = self.basescore
	    @temporal = self.temporalscore
	    @environmental = self.environmentalscore(self.adjustedtemporalscore(self.adjustedbasescore(@adjimpact, @exploitability)))  
	  end
	  
	  def adjustedimpactscore
	    tmp = []
	    tmp[0] = 10
	    tmp[1] = 10.41*(1-(1-@ci.abs*@cr.abs)*(1-@ii.abs*@ir.abs)*(1-@ai.abs*@ar.abs))
	    adjustedimpactscore = tmp.min
	  end
	  
	  def adjustedbasescore(adjustedimpact, exploitabilityscore)
	    adjustedbasescore = (0.6*adjustedimpact + 0.4 * exploitabilityscore - 1.5) * impactfunction(adjustedimpact)
	  end
	  
	  def adjustedtemporalscore(adjustedbasescore)
	    adjustedtemporalscore = adjustedbasescore * @ex.abs * @rl.abs * @rc.abs
	  end
	  
	  def exploitabilityscore
	    exploitability = 20 * @ac.abs * @au.abs * @av.abs
	  end
	  
	  def environmentalscore(adjustedtemporalscore)
	    environmentalscore = (adjustedtemporalscore + (10 - adjustedtemporalscore) * (@cdp == -1 ? 0 : @cdp.abs)) * @td.abs
	    
	    return environmentalscore == 0.0 ? "Undefined" : environmentalscore
	  end
	  
	  def overallscore
	    if self.noenvironmental
	      if self.notemporal
	        overallscore = @base
	      else
	        overallscore = @temporal
	      end
	    else
	      overallscore = @environmental
	    end
	    return overallscore
	  end
	  
	  def impactfunction(impact)
	  	return impact != 0 ? 1.176 : 0.0
	  end
	  
	  def impactscore
	    impact = 10.41*(1.0-(1.0-@ci.abs)*(1.0-@ii.abs)*(1.0-@ai.abs))
	  end
	  
	  def basescore
	    basescore = (0.6 * @impact + 0.4 * @exploitability - 1.5) * impactfunction(@impact)
	  end
	  
	  def temporalscore
	    temporalscore = @base * @ex.abs * @rl.abs * @rc.abs

	    return temporalscore == 0.0 ? "Undefined" : temporalscore
	  end
	end
end
