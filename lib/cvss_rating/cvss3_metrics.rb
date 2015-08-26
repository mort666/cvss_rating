module Cvss3
	class Metrics
		# Base Metrics
		ATTACK_VECTOR = { :physical => 0.55, :local => 0.55, :adjacent_network => 0.62, :network => 0.85, :not_defined => 0.85 }
	  	ATTACK_COMPLEXITY = { :high => 0.44, :low => 0.77, :not_defined => 0.77 }
	  	
	  	PRIVILEGE_REQUIRED = { :not_defined => 0.85, :none => 0.85, :low => 0.62, :high => 0.27 }
	  	PRIVILEGE_REQUIRED_CHANGED = { :not_defined => 0.85, :none => 0.85, :low => 0.68, :high => 0.50 }
	  
	  	USER_INTERACTION = {:not_defined => 0.85, :none => 0.85, :required => 0.62 }

	  	CIA_IMPACT = { :none => 0.0, :low => 0.22, :high => 0.56, :not_defined => 0.56 }
	  
	  	# Environmental Metrics
	  	CIA_REQUIREMENT = { :low => 0.5, :medium => 1.0, :high => 1.50, :not_defined => 1.0 }

	  	# Temporal Metrics
	  	EXPLOITABILITY = { :unproven => 0.91, :poc => 0.94, :functional =>  0.97, :high => 1.0, :not_defined => 1.0 }

	  	REMEDIATION_LEVEL = { :official => 0.95, :temporary => 0.96, :workaround =>  0.97, :unavailable => 1.0, :not_defined => 1.0 }
	  	
	  	REPORT_CONFIDENCE = { :unknown => 0.92, :reasonable => 0.96, :confirmed => 1.0, :not_defined => 1.0 }
	  
	  	# Key Lookup values

	  	ATTACK_VECTOR_KEY = { :physical => 'P', :local => 'L', :adjacent_network => 'A', :network => 'N' }
	  	ATTACK_COMPLEXITY_KEY = { :high => 'H', :low => 'L' }
	  	PRIVILEGE_REQUIRED_KEY = { :none => 'N', :low => 'L', :high => 'H' }
	  	PRIVILEGE_REQUIRED_CHANGED_KEY = { :none => 'N', :low => 'L', :high => 'H' }
	  	USER_INTERACTION_KEY = { :none => 'N', :required => 'R' }

	  	SCOPE_KEY = { :changed => 'C', :unchanged => 'U' }
	  
	  	CIA_IMPACT_KEY = { :none => 'N', :low => 'L', :high => 'H' }
	  
	  	CIA_REQUIREMENT_KEY = { :low => 'L', :medium => 'M', :high => 'H', :notdefined => 'ND' }
	  
	  	EXPLOITABILITY_KEY = { :unproven => 'U', :poc => 'P', :functional => 'F', :high => 'H', :not_defined => 'ND' }
	  	REMEDIATION_LEVEL_KEY = { :official => 'O', :temporary => "T", :workaround =>  'W', :unavailable => 'U', :not_defined => 'ND' }
	  	REPORT_CONFIDENCE_KEY = { :unknown => 'U', :reasonable => 'R', :confirmed => 'C', :not_defined => 'ND' }

	  	MODIFIED_ATTACK_VECTOR_KEY = { :physical => 'P', :local => 'L', :adjacent_network => 'A', :network => 'N' }
	  	MODIFIED_ATTACK_COMPLEXITY_KEY = { :high => 'H', :low => 'L' }
	  	MODIFIED_PRIVILEGE_REQUIRED_KEY = { :none => 'N', :low => 'L', :high => 'H' }
	  	MODIFIED_PRIVILEGE_REQUIRED_CHANGED_KEY = { :none => 'N', :low => 'L', :high => 'H' }
	  	MODIFIED_USER_INTERACTION_KEY = { :none => 'N', :required => 'R' }

	  	MODIFIED_SCOPE_KEY = { :changed => 'C', :unchanged => 'U' }
	  
	  	MODIFIED_CIA_IMPACT_KEY = { :none => 'N', :low => 'L', :high => 'H' }
	end
end