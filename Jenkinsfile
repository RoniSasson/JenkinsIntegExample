.vision_analysis:
  variables:
    VISION_ARTIFACT_ID: "2901"
    VISION_MAX_THREAT_LEVEL: "High"
    VISION_MAX_HIGHLIGHTED_ISSUES: "10"
    VISION_MAX_HIGHLIGHTED_CVES: "10"
    VISION_MAX_HIGHLIGHTED_EXPOSURES: "10"
    VISION_MAX_MALICIOUS_FILES: "10"
  image:
    name: ${VISION_CLI_REGISTRY}/vision_analysis:${VISION_ANALYSIS_TAG}
    entrypoint: ['']
  script:
    - vdoo_analysis --version
    # Vision analysis: Upload, Analyze and wait for completion. Get final status and results. 
    - echo "Upload & Analyze------------------"
    - vdoo_analysis analyze --token ${VISION_TOKEN} --artifact-id ${VISION_ARTIFACT_ID} --base_url ${VISION_BASE_URL} --image-path ${VISION_ARTIFACT_FILE_TO_UPLOAD} --verbose --output-uuid new_uuid.txt -n gitlab_ci_version 
    - NEW_UUID=$(cat ./new_uuid.txt)
    - vdoo_analysis images get_status --token ${VISION_TOKEN} --image-uuid ${NEW_UUID} --base_url ${VISION_BASE_URL}
    - vdoo_analysis images get_results --image-uuid ${NEW_UUID} --token ${VISION_TOKEN} --base_url ${VISION_BASE_URL} --scope all > vision_analysis_report.json
    # Decision on results:  Check Vision results vs. thresholds per your policy
    - |-
        # Parse the analysis results
        report_threat_level=`cat vision_analysis_report.json | jq -r '."analysis_summary"."threat_level"'`
        report_threat_level_val=`case ${report_threat_level} in "None") echo "20";; "Very High") echo "10";; "High") echo "8";; "Medium") echo "6";; "Low") echo "4";; "Very Low") echo "2";; esac`
        report_cves=`cat vision_analysis_report.json | jq -r '."analysis_summary"."highlighted_issues_count"."cves_count"'`
        report_exposures=`cat vision_analysis_report.json | jq -r '."analysis_summary"."highlighted_issues_count"."exposures_count"'`
        report_highlighted_total="$(($report_cves+$report_exposures))"
        report_malicious_files=`cat vision_analysis_report.json | jq -r '."analysis_summary"."highlighted_issues_count"."malicious_files_count"'`
        max_threat_level_val=`case ${VISION_MAX_THREAT_LEVEL} in "None") echo "20";; "Very High") echo "10";; "High") echo "8";; "Medium") echo "6";; "Low") echo "4";; "Very Low") echo "2";; esac`
        
        # Check the analysis results against the thresholds
        if [[ ${report_threat_level_val} -gt ${max_threat_level_val} ]] ; then
            echo "Analysis failed due to threat level too high - ${report_threat_level} vs. ${VISION_MAX_THREAT_LEVEL}"
            exit 1
        fi


        if [[ $((report_highlighted_total)) -gt $((VISION_MAX_HIGHLIGHTED_ISSUES)) ]] ; then
            echo "Analysis failed due to too many highlighted issues (${report_highlighted_total} > ${VISION_MAX_HIGHLIGHTED_ISSUES})"
            exit 1
        fi

        if [[ ${report_cves} -gt ${VISION_MAX_HIGHLIGHTED_CVES} ]] ; then
            echo "Analysis failed due to too many CVEs (${report_cves} > ${VISION_MAX_HIGHLIGHTED_CVES})"
            exit 1
        fi

        if [[ ${report_exposures} -gt ${VISION_MAX_HIGHLIGHTED_EXPOSURES} ]] ; then
            echo "Analysis failed due to too many exposures (${report_exposures} > ${VISION_MAX_HIGHLIGHTED_EXPOSURES})"
            exit 1
        fi

        if [[ ${report_malicious_files} -gt ${VISION_MAX_MALICIOUS_FILES} ]] ; then
            echo "Analysis failed due to too many malicious_files (${report_malicious_files} > ${VISION_MAX_MALICIOUS_FILES})"
            exit 1
        fi

  artifacts:
    when: always
    paths:
      - vision_analysis_report.json
    expire_in: 1 week
