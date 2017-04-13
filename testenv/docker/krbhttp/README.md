# Intergation Test Instance for TEST.GOKRB5

DO NOT USE THIS CONTAINER FOR ANY PRODUCTION USE!!!

To run:

docker run -v /etc/localtime:/etc/localtime:ro -p 80:80 -p 443:443 --rm --name gokrb5-TEST-httpd jcmturner/jtnet:gokrb5-test-httpd-v1.0

To build:
docker build -t jcmturner/jtnet:gokrb5-test-httpd-v1.0 --force-rm=true --rm=true .
docker push jcmturner/jtnet:gokrb5-test-httpd-v1.0
