/**
 * DevSecOps Toolkit — Jenkinsfile Template
 * Copy this file into any project repo and set the config block below.
 * No other changes needed to get full SAST + DAST + container scanning.
 */

@Library('devsecops-shared-lib') _

pipeline {
    agent any

    environment {
        IMAGE_NAME = 'sample-app'
        APP_PORT   = '5000'
    }

    stages {
        stage('DevSecOps Pipeline') {
            steps {
                script {
                    devsecops.fullScan(
                        imageName:     env.IMAGE_NAME,
                        appPort:       env.APP_PORT,
                        dockerContext: './sample-app',
                        srcDir:        './sample-app',
                        policyFile:    'policy.yml'
                    )
                }
            }
        }
    }

    post {
        always {
            echo "Pipeline complete. Check the Report stage for security findings."
        }
        failure {
            echo "Build failed — a security policy threshold was exceeded."
        }
    }
}