pipeline {
    agent any

    stages {
        stage('Build') {
            steps {
                script {
                    // This is a placeholder for your actual build process
                    sh 'cp full_filesystem.bin jenkins_newly_built_image.bin'
                    stash(name: 'image_to_analyze', includes: 'jenkins_newly_built_image.bin')
                }
            }
        }

        stage('Run Vision analysis') {
            agent {
                docker {
                    image "${env.VISION_CLI_REGISTRY}/vision_analysis:${env.VISION_ANALYSIS_TAG}"
                    reuseNode true
                }
            }
            options {
                timeout(time: 60, unit: 'MINUTES')
            }
            steps {
                script {
                    unstash 'image_to_analyze'
                    withCredentials([string(credentialsId: 'VISION_TOKEN', variable: 'VISION_TOKEN')]) {
                        sh '''#!/bin/bash
                            # These parameters for this run are for this example only. Set your own values for your own run.
                            export VISION_ARTIFACT_ID=2901
                            export VISION_MAX_THREAT_LEVEL="High"
                            export VISION_MAX_HIGHLIGHTED_ISSUES=10
                            export VISION_MAX_HIGHLIGHTED_CVES=10
                            export VISION_MAX_HIGHLIGHTED_EXPOSURES=10
                            export VISION_MAX_MALICIOUS_FILES=10

                            vdoo_analysis --version

                            # Vision analysis: Upload, Analyze and wait for completion. Get final status and results.
                            echo "Upload & Analyze------------------"
                            vdoo_analysis analyze --token ${VISION_TOKEN} --base_url ${VISION_BASE_URL} \\
                                --artifact-id ${VISION_ARTIFACT_ID} --image-path full_filesystem_new_build.bin \\
                                -n jenkins_ci_version | jq -r .image_uuid > new_image_uuid.txt

                            echo "New image id:"
                            cat new_image_uuid.txt

                            # Get the analysis results
                            vdoo_analysis images get_results --token ${VISION_TOKEN} --base_url ${VISION_BASE_URL} --image-uuid `cat new_image_uuid.txt` \\
                                --scope all > vision_analysis_report.json

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

                            echo "Done"
                        '''
                    }
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: 'vision_analysis_report.json', fingerprint: true
                }
            }
        }
    }
}
