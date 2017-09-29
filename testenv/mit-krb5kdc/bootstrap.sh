#!/bin/bash

rm /etc/localtime
ln -s /usr/share/zoneinfo/Europe/London /etc/localtime
setenforce 0
sed -i "s/SELINUX=enforcing/SELINUX=permissive/g" /etc/sysconfig/selinux

yum update -y && yum clean all
yum install -y tcpdump ntp docker net-tools

systemctl stop firewalld
systemctl disable firewalld
systemctl enable ntpd docker
systemctl start docker
systemctl stop docker

#Some storage issue with docker on centos 7.1 hack
rm -f /etc/sysconfig/docker-storage
rm -rf /var/lib/docker

cat <<EOF >> /etc/sysctl.conf
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF

cp /vagrant/*.service /etc/systemd/system/
systemctl enable krb5kdc krb5kdc-latest krb5kdc-older httpd

reboot

#systemctl start docker krb5kdc krb5kdc-latest krb5kdc-older
