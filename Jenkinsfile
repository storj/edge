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
								// make a backup of the mod file in case, for later linting
								sh 'cp go.mod .build/go.mod.orig'
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
								sh 'check-copyright'
								sh 'check-large-files'
								sh 'check-imports -race ./...'
								sh 'check-peer-constraints -race'
								sh 'check-atomic-align ./...'
								sh 'check-monkit ./...'
								sh 'check-errs ./...'
								sh 'staticcheck ./...'
								sh 'golangci-lint --concurrency 16 run --config /go/ci/.golangci.yml'
								sh 'check-downgrades'
								sh 'check-mod-tidy -mod .build/go.mod.orig'

								// A bit of an explanation around this shellcheck command:
								// * Find all scripts recursively that have the .sh extension, except for "testsuite@tmp" which Jenkins creates temporarily.
								// * Use + instead of \ so find returns a non-zero exit if any invocation of shellcheck returns a non-zero exit.
								sh 'find . -path ./testsuite@tmp -prune -o -name "*.sh" -type f -exec "shellcheck" "-x" "--format=gcc" {} +;'

								dir("testsuite") {
									sh 'check-imports -race ./...'
									sh 'check-atomic-align ./...'
									sh 'check-monkit ./...'
									sh 'check-errs ./...'
									sh 'staticcheck ./...'
									sh 'golangci-lint --concurrency 16 run --config /go/ci/.golangci.yml'
									sh 'check-mod-tidy -mod ../.build/testsuite.go.mod.orig'
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
										sh 'go test -parallel 16 -p 16 -vet=off ${COVERFLAGS} -timeout 20m -json -race ./... 2>&1 | tee .build/tests.json | xunit -out .build/tests.xml'
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
											sh 'go vet -p 16 ./...'
											sh 'go test -parallel 16 -p 16 -vet=off -timeout 20m -json -race ./... 2>&1 | tee ../.build/testsuite.json | xunit -out ../.build/testsuite.xml'
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
								sh 'GOOS=linux   GOARCH=amd64 go vet -p 16 ./...'
								sh 'GOOS=linux   GOARCH=386   go vet -p 16 ./...'
								sh 'GOOS=linux   GOARCH=arm64 go vet -p 16 ./...'
								sh 'GOOS=linux   GOARCH=arm   go vet -p 16 ./...'
								sh 'GOOS=windows GOARCH=amd64 go vet -p 16 ./...'
								sh 'GOOS=windows GOARCH=386   go vet -p 16 ./...'
								// Use kqueue to avoid needing cgo for verification.
								sh 'GOOS=darwin  GOARCH=amd64 go vet -p 16 -tags kqueue ./...'
								sh 'GOOS=darwin  GOARCH=arm64 go vet -p 16 -tags kqueue ./...'
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
			stage('Integration set up') {
				checkout scm

				env.STORJ_SIM_POSTGRES = 'postgres://postgres@postgres:5432/teststorj?sslmode=disable'
				env.STORJ_SIM_REDIS = 'redis:6379'
				env.GATEWAY_DOMAIN = 'gateway.local'
				env.GATEWAY_IP = '10.11.0.10'
				sh 'docker run --rm -d -e POSTGRES_HOST_AUTH_METHOD=trust --name postgres-gateway-mt-$BUILD_NUMBER postgres:12.3'
				sh 'docker run --rm -d --name redis-gateway-mt-$BUILD_NUMBER redis:latest'
				sh '''until $(docker logs postgres-gateway-mt-$BUILD_NUMBER | grep "database system is ready to accept connections" > /dev/null)
					do printf '.'
					sleep 5
					done
				'''
				sh 'docker exec postgres-gateway-mt-$BUILD_NUMBER createdb -U postgres teststorj'
				sh 'docker run -u root:root --rm -i -d --name mintsetup-gateway-mt-$BUILD_NUMBER -v $PWD:$PWD -w $PWD --entrypoint $PWD/jenkins/test-mint.sh -e GATEWAY_DOMAIN -e STORJ_SIM_POSTGRES -e STORJ_SIM_REDIS --link redis-gateway-mt-$BUILD_NUMBER:redis --link postgres-gateway-mt-$BUILD_NUMBER:postgres storjlabs/golang:1.17.1'
				// Wait until the docker command above prints out the keys before proceeding
				output = sh (script: '''#!/bin/bash
					set -e +x
					echo "listing"
					ls $PWD/jenkins
					t="0"
					while true; do
						logs=$(docker logs mintsetup-gateway-mt-$BUILD_NUMBER -t --since "$t" 2>&1)
						keys=$(echo "$logs" | grep "Finished access_key_id" || true)
						if [ ! -z "$keys" ]; then
							echo "$logs"
							echo "found keys $keys"
							echo "ACCESS_KEY_ID=$(echo "$keys" | rev |  cut -d "," -f2 | cut -d ":" -f1 | rev)"
							echo "SECRET_KEY=$(echo "$keys" | rev |  cut -d "," -f1 | cut -d ":" -f1 | rev)"
							break
						fi
						t=$(echo -E "$logs" | tail -n 1 | cut -d " " -f1)
						echo "printing logs"
						echo "$logs"
						sleep 5
					done
				''', returnStdout: true).trim().split('\n')
				env.ACCESS_KEY_ID = output.findAll{ it.startsWith('ACCESS_KEY_ID=') }[0].split('=')[1]
				env.SECRET_KEY = output.findAll{ it.startsWith('SECRET_KEY=') }[0].split('=')[1]
				println output.join('\n')

				sh 'docker network create minttest-gateway-mt-$BUILD_NUMBER --subnet=10.11.0.0/16'
				sh 'docker network connect --alias $GATEWAY_DOMAIN --ip $GATEWAY_IP minttest-gateway-mt-$BUILD_NUMBER mintsetup-gateway-mt-$BUILD_NUMBER'
				sh 'docker pull storjlabs/gateway-mint:latest'
			}

			stage('Integration') {
				def branchedStages = [:]

				tests = ['https', 'awscli', 'awscli_multipart', 'duplicity', 'duplicati']
				tests.each { test ->
					branchedStages["Test $test"] = {
						stage("Test $test") {
							sh "docker run -u root:root --rm -e AWS_ENDPOINT=\"https://\${GATEWAY_DOMAIN}:7778\" -e AWS_ACCESS_KEY_ID=\${ACCESS_KEY_ID} -e AWS_SECRET_ACCESS_KEY=\${SECRET_KEY} -v \$PWD:\$PWD -w \$PWD --name test-$test-\$BUILD_NUMBER --entrypoint \$PWD/testsuite/integration/${test}.sh --network minttest-gateway-mt-\$BUILD_NUMBER storjlabs/ci:latest"
						}
					}
				}

				// todo: aws-sdk-go test is disabled as the tests fail with multi-part validation disabled.
				mintTests = ['aws-sdk-java', 'awscli', 'minio-go', 's3cmd']
				mintTests.each { test ->
					branchedStages["Mint $test"] = {
						stage("Mint $test") {
							sh "docker run --rm -e SERVER_ENDPOINT=\${GATEWAY_DOMAIN}:7777 -e ACCESS_KEY=\${ACCESS_KEY_ID} -e SECRET_KEY=\${SECRET_KEY} -e ENABLE_HTTPS=0 --network minttest-gateway-mt-\${BUILD_NUMBER} --name mint-$test-\$BUILD_NUMBER storjlabs/gateway-mint:latest $test"
						}
					}
				}

				parallel branchedStages
			}

			// We run aws-sdk-php and aws-sdk-ruby tests sequentially because
			// each of them contains a test that lists buckets and interferes
			// with other tests that run in parallel.
			//
			// TODO: run each Mint test with different credentials.

			// todo: aws-sdk-php test is disabled as the tests fail with multi-part validation disabled.
			// stage('Integration Mint/PHP') {
			// 	sh "docker run --rm -e SERVER_ENDPOINT=\${GATEWAY_DOMAIN}:7777 -e ACCESS_KEY=\${ACCESS_KEY_ID} -e SECRET_KEY=\${SECRET_KEY} -e ENABLE_HTTPS=0 --network minttest-gateway-mt-\${BUILD_NUMBER} --name mint-aws-sdk-php-\$BUILD_NUMBER storjlabs/gateway-mint:latest aws-sdk-php"
			// }
			stage('Integration Mint/Ruby') {
				sh "docker run --rm -e SERVER_ENDPOINT=\${GATEWAY_DOMAIN}:7777 -e ACCESS_KEY=\${ACCESS_KEY_ID} -e SECRET_KEY=\${SECRET_KEY} -e ENABLE_HTTPS=0 --network minttest-gateway-mt-\${BUILD_NUMBER} --name mint-aws-sdk-ruby-\$BUILD_NUMBER storjlabs/gateway-mint:latest aws-sdk-ruby"
			}
		}
		catch(err) {
			throw err
		}
		finally {
			sh 'docker logs mintsetup-gateway-mt-$BUILD_NUMBER || true'
			sh 'docker stop mintsetup-gateway-mt-$BUILD_NUMBER || true'
			sh 'docker stop postgres-gateway-mt-$BUILD_NUMBER || true'
			sh 'docker stop redis-gateway-mt-$BUILD_NUMBER || true'
			sh 'docker network rm minttest-gateway-mt-$BUILD_NUMBER || true'
			sh "chmod -R 777 ." // ensure Jenkins agent can delete the working directory
			deleteDir()
		}
	}
}
