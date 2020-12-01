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
			def dockerImage = docker.build("storj-ci", "--pull https://github.com/storj/ci.git")
			dockerImage.inside('-u root:root --cap-add SYS_PTRACE -v "/tmp/gomod":/go/pkg/mod') {
				try {
					stage('Build') {
						checkout scm

						sh 'mkdir -p .build'

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
								// TODO: reenable,
								//	currently there are few packages that contain non-standard license formats.
								//sh 'go-licenses check ./...'
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
										sh 'go vet ./...'
										sh 'go test -parallel 4 -p 6 -vet=off ${COVERFLAGS} -timeout 20m -json -race ./... 2>&1 | tee .build/testsuite.json | xunit -out .build/testsuite.xml'
										// TODO enable this later
										// sh 'check-clean-directory'
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
		stage('mint-tests'){
			try {
				checkout scm

				env.STORJ_SIM_POSTGRES = 'postgres://postgres@postgres:5432/teststorj?sslmode=disable'
				env.STORJ_SIM_REDIS = 'redis:6379'
				sh 'docker run --rm -d -e POSTGRES_HOST_AUTH_METHOD=trust --name postgres-$BUILD_NUMBER postgres:12.3'
				sh 'docker run --rm -d --name redis-$BUILD_NUMBER redis:latest'
				sh '''until $(docker logs postgres-$BUILD_NUMBER | grep "database system is ready to accept connections" > /dev/null)
					do printf '.'
					sleep 5
					done
				'''
				sh 'docker exec postgres-$BUILD_NUMBER createdb -U postgres teststorj'

				sh 'docker run -u root:root --rm -i -d --name mintsetup-$BUILD_NUMBER -v $PWD:$PWD -w $PWD --entrypoint $PWD/scripts/test-mint.sh -e BRANCH_NAME -e STORJ_SIM_POSTGRES -e STORJ_SIM_REDIS --link redis-$BUILD_NUMBER:redis --link postgres-$BUILD_NUMBER:postgres storjlabs/golang:1.15.5'
				// Wait until the docker command above prints out the keys before proceeding
				sh '''#!/bin/bash
						set -e +x
						t="0"
						while true; do
							logs=$(docker logs mintsetup-$BUILD_NUMBER -t --since "$t" 2>&1)
							keys=$(echo "$logs" | grep "Finished access_key_id" || true)
							if [ ! -z "$keys" ]; then
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

						echo "parsed keys ${ACCESS_KEY} ${SECRET_KEY}"
						docker network create minttest-$BUILD_NUMBER
						docker network connect --alias mintsetup minttest-$BUILD_NUMBER mintsetup-$BUILD_NUMBER
						docker run -e SERVER_ENDPOINT=mintsetup:7777 -e ACCESS_KEY=${ACCESS_KEY_ID} -e SECRET_KEY=${SECRET_KEY} -e ENABLE_HTTPS=0 --network minttest-$BUILD_NUMBER storjlabs/minio-mint:latest
				'''
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
}

