module Cvss3
  class Formulas
    EXPLOITABILITY_COEFFICIENT = 8.22
    IMPACT_COEFFICIENT = 6.42
    IMPACT_MOD_COEFFICIENT = 7.52

    def exploitability_sub_score(attack_vector_value, attack_complexity_value, privileges_required_value, user_interaction_value)
			exploitability_sub_score_value = EXPLOITABILITY_COEFFICIENT * attack_vector_value * attack_complexity_value * privileges_required_value * user_interaction_value

      exploitability_sub_score_value
    end

    def exploitability_sub_score_modified(attack_vector_value_modified, attack_complexity_value_modified,
                                          privileges_required_value_modified, user_interaction_value_modified)

      exploitability_sub_score_value_modified = EXPLOITABILITY_COEFFICIENT * attack_vector_value_modified * attack_complexity_value_modified * privileges_required_value_modified * user_interaction_value_modified

      exploitability_sub_score_value_modified
    end

    def impact_sub_score_base(availability_value, confidentiality_value, integrity_value)
      impact_sub_score_value = 1 - ((1 - confidentiality_value) * (1 - integrity_value) * (1 - availability_value))

      impact_sub_score_value
    end

    def impact_sub_score_modified_base(availability_value_modified, confidentiality_value_modified, integrity_value_modified,
                                       confidentiality_requirement_value, integrity_requirement_value, availability_requirement_value)

      impact_sub_score_value_modified = min(0.915, 1 - (1 - confidentiality_value_modified * confidentiality_requirement_value) * (1 - integrity_value_modified * integrity_requirement_value) * (1 - availability_value_modified * availability_requirement_value))

      impact_sub_score_value_modified
    end

    def cvss_base_formula(impact_sub_score_value, scope_value, exploitability_sub_score_value)
      if scope_value == 'unchanged'
        impact_value = IMPACT_COEFFICIENT * impact_sub_score_value
        cvss_base_value = min(10.0, impact_value + exploitability_sub_score_value)
      elsif scope_value == 'changed'
        impact_value = IMPACT_MOD_COEFFICIENT * (impact_sub_score_value - 0.029) - 3.25 * ((impact_sub_score_value - 0.02)**15)
        cvss_base_value = min(10.0, 1.08 * (impact_value + exploitability_sub_score_value))
          end

      cvss_base_value = if impact_sub_score_value <= 0
                          0.0
                        else
                          cvss_base_value.ceil2(1)
                         end

      cvss_base_value
    end

    def cvss_temporal_formula(cvss_base_value, exploit_code_maturity_value, remediation_level_value, report_confidence_value)
      cvss_temporal_value = cvss_base_value * exploit_code_maturity_value * remediation_level_value * \
                            report_confidence_value

      cvss_temporal_value = cvss_temporal_value.ceil2(1)

      cvss_temporal_value
    end

    def cvss_environmental_formula(impact_sub_score_value_modified, exploitability_sub_score_value_modified,
                                   exploit_code_maturity_value, remediation_level_value, report_confidence_value, scope_value_modified)

      if scope_value_modified == 'unchanged'
        impact_value_modified = IMPACT_COEFFICIENT * impact_sub_score_value_modified
        temp_score = min(10.0, impact_value_modified + exploitability_sub_score_value_modified)
        temp_score2 = temp_score.ceil2(1)
        temp_score3 = temp_score2 * exploit_code_maturity_value * remediation_level_value * report_confidence_value
      elsif scope_value_modified == 'changed'
        impact_value_modified = IMPACT_MOD_COEFFICIENT * (impact_sub_score_value_modified - 0.029) - 3.25 * ((impact_sub_score_value_modified - 0.02)**15)
        temp_score = min(10.0, 1.08 * (impact_value_modified + exploitability_sub_score_value_modified))
        temp_score2 = temp_score.ceil2(1)
        temp_score3 = temp_score2 * exploit_code_maturity_value * remediation_level_value * report_confidence_value
        end

      cvss_environmental_value = if impact_sub_score_value_modified <= 0
                                   0.0
                                 else
                                   temp_score3.ceil2(1)
                                 end

      cvss_environmental_value
    end

    def min(*values)
      values.min
    end
  end
end
