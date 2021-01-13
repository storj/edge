#!/usr/bin/env bash
set -euo pipefail

#setup tmpdir for testfiles and cleanup
tmpdir=$(mktemp -d -t tmp.XXXXXXXXXX)
cleanup(){
	rm -rf "$tmpdir"
}
trap cleanup EXIT

apt update
apt install -y curl unzip

# Install the awscli so I can do a quick test, ensure that all services are running.
cd /home && curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" && \
    unzip awscliv2.zip && \
    ./aws/install \

export PATH=/usr/local/bin:$PATH

server_endpoint="$SERVER_IP:$SERVER_PORT"
aws_endpoint="http://${server_endpoint}"
aws_virtual_endpoint="http://${GATEWAY_DOMAIN}:${SERVER_PORT}"
virtual_bucket=bob

# Prevent multipart uploads for this test.
aws configure set default.s3.multipart_threshold 1TB

# Create random test file to use later.
head -c 1MB </dev/urandom >"$tmpdir"/1MBFile

# Very basic check to ensure that everything is working
aws --endpoint "${aws_endpoint}" s3 ls
aws --endpoint "${aws_endpoint}" s3 mb s3://awstest
aws --endpoint "${aws_endpoint}" s3 cp "$tmpdir"/1MBFile s3://awstest
aws --endpoint "${aws_endpoint}" s3 cp s3://awstest/1MBFile "$tmpdir"/1MBFile_copy1
diff "$tmpdir"/1MBFile "$tmpdir"/1MBFile_copy1

# Begin virtual host requests
echo "${SERVER_IP} ${GATEWAY_DOMAIN} ${virtual_bucket}.${GATEWAY_DOMAIN}" >> /etc/hosts
aws configure set default.s3.addressing_style virtual

aws --endpoint "${aws_virtual_endpoint}" s3 mb s3://${virtual_bucket}
aws --endpoint "${aws_virtual_endpoint}" s3 cp "$tmpdir"/1MBFile s3://${virtual_bucket}
aws --endpoint "${aws_virtual_endpoint}" s3 cp s3://${virtual_bucket}/1MBFile "$tmpdir"/1MBFile_copy2
aws --endpoint "${aws_virtual_endpoint}" s3 rm s3://${virtual_bucket}/1MBFile
diff "$tmpdir"/1MBFile "$tmpdir"/1MBFile_copy2
