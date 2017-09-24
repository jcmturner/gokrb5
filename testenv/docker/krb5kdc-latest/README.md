# KDC Intergation Test Instance for TEST.GOKRB5

DO NOT USE THIS CONTAINER FOR ANY PRODUCTION USE!!!

To run:

docker run -v /etc/localtime:/etc/localtime:ro -p 88:88 -p 88:88/udp --rm --name gokrb5-TEST-kdc-lastest jcmturner/jtnet:gokrb5-test-kdc-latest-v1.0 &

To build:
docker build -t jcmturner/jtnet:gokrb5-test-kdc-latest-v1.0 --force-rm=true --rm=true .
docker push jcmturner/jtnet:gokrb5-test-kdc-latest-v1.0
