// todo: convert scripted syntax to declarative to match gateway-st
timeout(time: 26, unit: 'MINUTES') {
	node {
		stage('build'){
			def dockerImage = docker.image("storjlabs/ci:latest")
			dockerImage.pull()
			dockerImage.inside('-u root:root --cap-add SYS_PTRACE -v "/tmp/gomod":/go/pkg/mod') {
				try {
					stage('Build') {
						def branchedStages = [:]

						branchedStages["Environment"] = {
							stage("Environment") {
								checkout scm
								sh 'mkdir -p .build'
								sh 'go mod download'
								sh 'cd testsuite && go mod download'
							}
						}

						branchedStages["Environment: PostgreSQL & CockroachDB"] = {
							stage("Environment: PostgreSQL & CockroachDB") {
								sh 'service postgresql start'
								sh 'cockroach start-single-node --insecure --store=\'/tmp/crdb\' --listen-addr=localhost:26257 --http-addr=localhost:8080 --cache 512MiB --max-sql-memory 512MiB --background'
								sh 'psql -U postgres -c \'create database teststorj;\''
								sh 'cockroach sql --insecure --host=localhost:26257 -e \'create database testcockroach;\''
								sh 'use-ports -from 1024 -to 10000 &'
							}
						}

						parallel branchedStages
					}

					stage('Verification') {
						def branchedStages = [:]

						branchedStages["Lint"] = {
							stage("Lint") {
								withEnv([
									"GOLANGCI_LINT_CONFIG=/go/ci/.golangci.yml",
									"GOLANGCI_LINT_CONFIG_TESTSUITE=/go/ci/.golangci.yml",
								]){
									sh 'make lint'
								}
							}
						}

						branchedStages["Test"] = {
							stage("Test") {
								withEnv([
									"JSON=true",
									"SHORT=true",
									"SKIP_TESTSUITE=true",
									"STORJ_TEST_COCKROACH=cockroach://root@localhost:26257/testcockroach?sslmode=disable",
									"STORJ_TEST_POSTGRES=postgres://postgres@localhost/teststorj?sslmode=disable",
								]){
									try {
										sh 'make test 2>&1 | tee .build/tests.json | xunit -out .build/tests.xml'
									}
									catch(err) {
										throw err
									}
									finally {
										sh script: 'cat .build/tests.json | tparse -all -top -slow 100', returnStatus: true
										archiveArtifacts artifacts: '.build/tests.json'
										junit '.build/tests.xml'
									}
								}
							}
						}

						branchedStages["Testsuite"] = {
							stage("Testsuite") {
								withEnv([
									"JSON=true",
									"SHORT=false",
									"STORJ_TEST_COCKROACH=cockroach://root@localhost:26257/testcockroach?sslmode=disable",
									"STORJ_TEST_POSTGRES=postgres://postgres@localhost/teststorj?sslmode=disable",
								]){
									try {
										sh 'make --no-print-directory test-testsuite 2>&1 | tee .build/testsuite.json | xunit -out .build/testsuite.xml'
									}
									catch(err) {
										throw err
									}
									finally {
										sh script: 'cat .build/testsuite.json | tparse -all -top -slow 100', returnStatus: true
										archiveArtifacts artifacts: '.build/testsuite.json'
										junit '.build/testsuite.xml'
									}
								}
							}
						}

						branchedStages["Cross-Vet"] = {
							stage("Cross-Vet") {
								sh 'make cross-vet'
							}
						}

						parallel branchedStages
					}
				}
				catch(err) {
					throw err
				}
				finally {
					sh "chmod -R 777 ." // ensure Jenkins agent can delete the working directory
					deleteDir()
				}
			}
		}
		try {
			stage('Start integration environment') {
				checkout scm
				sh 'make integration-env-start'
			}

			stage('Run integration tests') {
				def tests = [:]
				tests['splunk-tests'] = {
					stage('splunk-tests') {
						sh 'make integration-splunk-tests'
					}
				}
				['awscli', 'awscli_multipart', 'duplicity', 'duplicati', 'rclone', 's3fs'].each { test ->
					tests["gateway-st-test ${test}"] = {
						stage("gateway-st-test ${test}") {
							sh "TEST=${test} make integration-gateway-st-tests"
						}
					}
				}
				['aws-sdk-go', 'aws-sdk-java', 'awscli', 'minio-go', 's3cmd'].each { test ->
					tests["mint-test ${test}"] = {
						stage("mint-test ${test}") {
							sh "TEST=${test} make integration-mint-tests"
						}
					}
				}
				parallel tests
			}

			// We run aws-sdk-php and aws-sdk-ruby tests sequentially because
			// each of them contains a test that lists buckets and interferes
			// with other tests that run in parallel.
			//
			// TODO: run each Mint test with different credentials.
			stage('mint-test aws-sdk-php') {
				sh 'TEST=aws-sdk-php make integration-mint-tests'
			}
			stage('mint-test aws-sdk-ruby') {
				sh 'TEST=aws-sdk-ruby make integration-mint-tests'
			}
		}
		catch(err) {
			sh 'make integration-env-logs'
			throw err
		}
		finally {
			if(fileExists('gateway-st/.build/rclone-integration-tests')) {
				zip zipFile: 'rclone-integration-tests.zip', archive: true, dir: 'gateway-st/.build/rclone-integration-tests'
				archiveArtifacts artifacts: 'rclone-integration-tests.zip'
			}
			sh 'make integration-env-purge'

			// ensure Jenkins agent can delete the working directory
			// this chmod command is allowed to fail, e.g. it may encounter
			// operation denied errors trying to change permissions of root
			// owned files put into the workspace by tests running inside
			// docker containers, but these files can still be cleaned up.
			sh "chmod -R 777 . || true"
			deleteDir()
		}
	}
}
