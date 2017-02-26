node {
    mvnHome = tool name: 'maven', type: 'maven'
    milestone 10
    stage('Continuous Integration') {
        checkout scm
        withMaven( maven: 'maven', mavenSettingsConfig: 'maven-global-settings') {
            sh "mvn versions:lock-snapshots"
            sh "mvn -Dmaven.test.failure.ignore -U -P release clean deploy"
        }
        junit '**/target/surefire-reports/TEST-*.xml'
        stash includes: '**/pom.xml', name: 'poms'
    }
}
milestone 20
input message: 'Release ?', ok: 'Release', submitter: 'ymenager'
milestone 30
node {
    mvnHome = tool name: 'maven', type: 'maven'
    stage('Release') {
        checkout scm
        unstash 'poms'
        def pom = readMavenPom file: 'pom.xml'
        def version = pom.version.replace("-SNAPSHOT", "")
        echo "Releasing version ${version}"
        withMaven( maven: 'maven', mavenSettingsConfig: 'maven-global-settings') {
            sh "mvn --batch-mode versions:set -DnewVersion=${version}"
        }
        withMaven( maven: 'maven', mavenSettingsConfig: 'maven-global-settings') {
            sh "mvn -Dmaven.test.failure.ignore -U clean deploy"
        }
        junit '**/target/surefire-reports/TEST-*.xml'
        archive '**/target/*.jar'
    }
    milestone 40
}