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
								sh 'make build-packages'
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
								sh 'check-mod-tidy'
								sh 'check-copyright'
								sh 'check-large-files'
								sh 'check-imports -race ./...'
								sh 'check-peer-constraints -race'
								sh 'check-atomic-align ./...'
								sh 'check-monkit ./...'
								sh 'check-errs ./...'
								sh 'check-deferloop ./...'
								sh 'staticcheck ./...'
								sh 'golangci-lint run --config /go/ci/.golangci.yml'
								sh 'check-downgrades'

								// A bit of an explanation around this shellcheck command:
								// * Find all scripts recursively that have the .sh extension, except for "testsuite@tmp" which Jenkins creates temporarily.
								// * Use + instead of \ so find returns a non-zero exit if any invocation of shellcheck returns a non-zero exit.
								sh 'find . -path ./testsuite@tmp -prune -o -name "*.sh" -type f -exec "shellcheck" "-x" "--format=gcc" {} +;'

								dir("testsuite") {
									sh 'check-imports -race ./...'
									sh 'check-atomic-align ./...'
									sh 'check-monkit ./...'
									sh 'check-errs ./...'
									sh 'check-deferloop ./...'
									sh 'staticcheck ./...'
									sh 'golangci-lint run --config /go/ci/.golangci.yml'
								}
							}
						}

						branchedStages["Test"] = {
							stage("Test") {
								withEnv([
									"STORJ_TEST_COCKROACH=cockroach://root@localhost:26257/testcockroach?sslmode=disable",
									"STORJ_TEST_POSTGRES=postgres://postgres@localhost/teststorj?sslmode=disable",
									"COVERFLAGS=${ env.BRANCH_NAME != 'main' ? '' : '-coverprofile=.build/coverprofile -coverpkg=./...'}"
								]){
									try {
										sh 'go test -parallel 4 -p 16 -vet=off ${COVERFLAGS} -timeout 20m -json -race -short ./... 2>&1 | tee .build/tests.json | xunit -out .build/tests.xml'
										// TODO enable this later
										// sh 'check-clean-directory'
									}
									catch(err) {
										throw err
									}
									finally {
										sh script: 'cat .build/tests.json | tparse -all -top -slow 100', returnStatus: true
										archiveArtifacts artifacts: '.build/tests.json'
										junit '.build/tests.xml'

										script {
											if(fileExists(".build/coverprofile")){
												sh script: 'filter-cover-profile < .build/coverprofile > .build/clean.coverprofile', returnStatus: true
												sh script: 'gocov convert .build/clean.coverprofile > .build/cover.json', returnStatus: true
												sh script: 'gocov-xml  < .build/cover.json > .build/cobertura.xml', returnStatus: true
												cobertura coberturaReportFile: '.build/cobertura.xml'
											}
										}
									}
								}
							}
						}

						branchedStages["Testsuite"] = {
							stage("Testsuite") {
								withEnv([
									"STORJ_TEST_COCKROACH=cockroach://root@localhost:26257/testcockroach?sslmode=disable",
									"STORJ_TEST_POSTGRES=postgres://postgres@localhost/teststorj?sslmode=disable",
								]){
									try {
										dir('testsuite') {
											sh 'go vet ./...'
											sh 'go test -parallel 4 -p 16 -vet=off -timeout 20m -json -race ./... 2>&1 | tee ../.build/testsuite.json | xunit -out ../.build/testsuite.xml'
										}
									}
									catch(err) {
										throw err
									}
								}
							}
						}

						branchedStages["Go Compatibility"] = {
							stage("Go Compatibility") {
								sh 'GOOS=linux   GOARCH=amd64 go vet ./...'
								sh 'GOOS=linux   GOARCH=386   go vet ./...'
								sh 'GOOS=linux   GOARCH=arm64 go vet ./...'
								sh 'GOOS=linux   GOARCH=arm   go vet ./...'
								sh 'GOOS=windows GOARCH=amd64 go vet ./...'
								sh 'GOOS=windows GOARCH=386   go vet ./...'
								// Use kqueue to avoid needing cgo for verification.
								sh 'GOOS=darwin  GOARCH=amd64 go vet -tags kqueue ./...'
								sh 'GOOS=darwin  GOARCH=arm64 go vet -tags kqueue ./...'
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
