FROM centos:latest
MAINTAINER Jonathan Turner <jt@jtnet.co.uk>

EXPOSE 88

RUN yum install -y \
  tcpdump krb5-workstation vim \
  ncurses telnet ncurses-devel tcl net-tools \
 && yum groupinstall "Development Tools" -y \
 && yum clean all

ADD krb5-1.15.1.tar.gz /tmp
RUN cd /tmp && \
  tar -xvzf krb5-1.15.1.tar.gz && cd krb5-1.15.1/src && \
  ./configure && make && make install

ADD krb5.conf /etc/krb5.conf
ADD kdc.conf /var/kerberos/krb5kdc/kdc.conf
ADD kadm5.acl /var/kerberos/krb5kdc/kadm5.acl
ADD krb5kdc-init.sh /opt/krb5/bin/krb5kdc-init.sh
RUN mkdir -p /opt/krb5/log && \
  mkdir -p /var/log/kerberos && \
  chmod 700 /opt/krb5/bin/krb5kdc-init.sh && /opt/krb5/bin/krb5kdc-init.sh && \
  ln -sf /dev/stdout /var/log/krb5kdc.log

ENTRYPOINT ["/usr/sbin/krb5kdc", "-n"]

RUN yum update -y && yum clean all
