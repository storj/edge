timeout(time: 26, unit: 'MINUTES') {
	node {
		stage('build'){
			def dockerImage = docker.build("storj-ci", "--pull git://github.com/storj/ci.git#main")
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
								sh 'check-imports ./...'
								sh 'check-peer-constraints'
								sh 'storj-protobuf --protoc=$HOME/protoc/bin/protoc lint'
								sh 'storj-protobuf --protoc=$HOME/protoc/bin/protoc check-lock'
								sh 'check-atomic-align ./...'
								sh 'check-monkit ./...'
								sh 'check-errs ./...'
								sh 'staticcheck ./...'
								sh 'golangci-lint --concurrency 16 run --config /go/ci/.golangci.yml'
								sh 'check-downgrades'
								sh 'check-mod-tidy -mod .build/go.mod.orig'
								// TODO: reenable,
								//	currently there are few packages that contain non-standard license formats.
								//sh 'go-licenses check ./...'

								dir("testsuite") {
									sh 'check-imports ./...'
									sh 'check-atomic-align ./...'
									sh 'check-monkit ./...'
									sh 'check-errs ./...'
									sh 'staticcheck ./...'
									sh 'golangci-lint --concurrency 16 run --config /go/ci/.golangci.yml'
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
										sh 'go vet -p 16 ./...'
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
									"COVERFLAGS=${ env.BRANCH_NAME != 'main' ? '' : '-coverprofile=../.build/coverprofile -coverpkg=./...'}"
								]){
									try {
										dir('testsuite') {
											sh 'go vet -p 16 ./...'
											sh 'go test -parallel 16 -p 16 -vet=off ${COVERFLAGS} -timeout 20m -json -race ./... 2>&1 | tee ../.build/testsuite.json | xunit -out ../.build/testsuite.xml'
										}
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
		stage('integration-tests'){
			try {
				checkout scm

				env.STORJ_SIM_POSTGRES = 'postgres://postgres@postgres:5432/teststorj?sslmode=disable'
				env.STORJ_SIM_REDIS = 'redis:6379'
				env.GATEWAY_DOMAIN = 'gateway.local'
				sh 'docker run --rm -d -e POSTGRES_HOST_AUTH_METHOD=trust --name postgres-gateway-mt-$BUILD_NUMBER postgres:12.3'
				sh 'docker run --rm -d --name redis-gateway-mt-$BUILD_NUMBER redis:latest'
				sh '''until $(docker logs postgres-gateway-mt-$BUILD_NUMBER | grep "database system is ready to accept connections" > /dev/null)
					do printf '.'
					sleep 5
					done
				'''
				sh 'docker exec postgres-gateway-mt-$BUILD_NUMBER createdb -U postgres teststorj'

				sh 'docker run -u root:root --rm -i -d --name mintsetup-gateway-mt-$BUILD_NUMBER -v $PWD:$PWD -w $PWD --entrypoint $PWD/jenkins/test-mint.sh -e GATEWAY_DOMAIN -e STORJ_SIM_POSTGRES -e STORJ_SIM_REDIS --link redis-gateway-mt-$BUILD_NUMBER:redis --link postgres-gateway-mt-$BUILD_NUMBER:postgres storjlabs/golang:1.16'
				// Wait until the docker command above prints out the keys before proceeding
				sh '''#!/bin/bash
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
								ACCESS_KEY_ID=$(echo "$keys" | rev |  cut -d "," -f2 | cut -d ":" -f1 | rev)
								SECRET_KEY=$(echo "$keys" | rev |  cut -d "," -f1 | cut -d ":" -f1 | rev)
								break
							fi
							t=$(echo -E "$logs" | tail -n 1 | cut -d " " -f1)
							echo "printing logs"
							echo "$logs"
							sleep 5
						done

						gatewayip=10.11.0.10

						echo "parsed keys ${ACCESS_KEY_ID} ${SECRET_KEY}"
						docker network create minttest-gateway-mt-$BUILD_NUMBER --subnet=10.11.0.0/16
						docker network connect --alias mintsetup --ip $gatewayip minttest-gateway-mt-$BUILD_NUMBER mintsetup-gateway-mt-$BUILD_NUMBER
						# note the storj-ci docker image is used below, it already has duplicati etc. installed
						docker run -u root:root --rm -e AWS_ENDPOINT="http://$gatewayip:7777" -e AWS_ACCESS_KEY_ID=${ACCESS_KEY_ID} -e AWS_SECRET_ACCESS_KEY=${SECRET_KEY} -v $PWD:$PWD -w $PWD --name testawscli-$BUILD_NUMBER --entrypoint $PWD/testsuite/integration/run.sh --network minttest-gateway-mt-$BUILD_NUMBER storj-ci
						docker pull storjlabs/minio-mint:latest
						docker run --rm -e SERVER_ENDPOINT=mintsetup:7777 -e ACCESS_KEY=${ACCESS_KEY_ID} -e SECRET_KEY=${SECRET_KEY} -e ENABLE_HTTPS=0 --network minttest-gateway-mt-$BUILD_NUMBER storjlabs/minio-mint:latest
				'''
			}
			catch(err) {
				throw err
			}
			finally {
				sh 'docker stop mintsetup-gateway-mt-$BUILD_NUMBER || true'
				sh 'docker stop postgres-gateway-mt-$BUILD_NUMBER || true'
				sh 'docker stop redis-gateway-mt-$BUILD_NUMBER || true'
				sh 'docker network rm minttest-gateway-mt-$BUILD_NUMBER || true'
				sh "chmod -R 777 ." // ensure Jenkins agent can delete the working directory
				deleteDir()
			}
		}
	}
}
