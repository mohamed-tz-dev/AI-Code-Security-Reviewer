pipeline {
  agent any
  stages {
    stage('Trigger Security Scan') {
      steps {
        script {
          sh '''
            curl -X POST \
              -H "Content-Type: application/json" \
              -H "Authorization: Bearer ${SECURITY_REVIEW_API_TOKEN}" \
              -d '{
                "repositoryUrl": "${GIT_URL}",
                "branch": "${BRANCH_NAME}",
                "commitSha": "${GIT_COMMIT}"
              }' \
              "${SECURITY_REVIEW_API_URL}/api/scans/github"
          '''
        }
      }
    }
  }
}
