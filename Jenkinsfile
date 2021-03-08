def withDockerNetwork(Closure inner) {
	try {
		networkId = UUID.randomUUID().toString()
		sh "docker network create ${networkId}"
		inner.call(networkId)
	} finally {
		sh "docker network rm ${networkId}"
	}
}

timeout(time: 26, unit: 'MINUTES') {
	node {
		stage('build'){
			def dockerImage = docker.build("storj-ci", "--pull git://github.com/storj/ci.git#main")
			dockerImage.inside('-u root:root --cap-add SYS_PTRACE -v "/tmp/gomod":/go/pkg/mod') {
				try {
					stage('Build') {
						checkout scm

						sh 'mkdir -p .build'
						// make a backup of the mod file in case, for later linting
						sh 'cp go.mod .build/go.mod.orig'
						sh 'service postgresql start'
						sh 'cockroach start-single-node --insecure --store=\'/tmp/crdb\' --listen-addr=localhost:26257 --http-addr=localhost:8080 --cache 512MiB --max-sql-memory 512MiB --background'
						sh 'make build-packages'
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
								sh 'golangci-lint --config /go/ci/.golangci.yml -j=2 run'
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
									sh 'golangci-lint --config /go/ci/.golangci.yml -j=2 run'
								}
							}
						}

						branchedStages["Test"] = {
							stage("Test") {
								withEnv([
									"COVERFLAGS=${ env.BRANCH_NAME != 'master' ? '' : '-coverprofile=.build/coverprofile -coverpkg=./...'}"
								]){
									try {
										sh 'go vet ./...'
										sh 'go test -parallel 4 -p 6 -vet=off ${COVERFLAGS} -timeout 20m -json -race ./... 2>&1 | tee .build/tests.json | xunit -out .build/tests.xml'
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
								   "COVERFLAGS=${ env.BRANCH_NAME != 'master' ? '' : '-coverprofile=.build/coverprofile -coverpkg=./...'}"
							   ]){
								  try {
									  sh 'cockroach sql --insecure --host=localhost:26257 -e \'create database testcockroach;\''
									  sh 'psql -U postgres -c \'create database teststorj;\''
									  sh 'use-ports -from 1024 -to 10000 &'
									  dir('testsuite') {
										 sh 'go vet ./...'
										 sh 'go test -parallel 4 -p 6 -vet=off ${COVERFLAGS} -timeout 20m -json -race ./... 2>&1 | tee ../.build/testsuite.json | xunit -out ../.build/testsuite.xml'
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
						docker run -u root:root --rm -e SERVER_IP=$gatewayip -e SERVER_PORT=7777 -e GATEWAY_DOMAIN -e AWS_ACCESS_KEY_ID=${ACCESS_KEY_ID} -e AWS_SECRET_ACCESS_KEY=${SECRET_KEY} -v $PWD:$PWD -w $PWD --name testawscli-$BUILD_NUMBER --entrypoint $PWD/jenkins/test-aws.sh --network minttest-gateway-mt-$BUILD_NUMBER storjlabs/golang:1.16
						# note the storj-ci docker image is used below, it already has duplicati etc. installed 
						docker run -u root:root --rm -e SERVER_IP=$gatewayip -e SERVER_PORT=7777 -e GATEWAY_DOMAIN -e AWS_ACCESS_KEY_ID=${ACCESS_KEY_ID} -e AWS_SECRET_ACCESS_KEY=${SECRET_KEY} -v $PWD:$PWD -w $PWD --name testawscli-$BUILD_NUMBER --entrypoint $PWD/testsuite/integration/run.sh --network minttest-gateway-mt-$BUILD_NUMBER storj-ci
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

