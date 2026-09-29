# Deliberately legacy SSH server for local scanner testing only.
# debian:stretch is EOL and ships an older OpenSSH that still permits
# weak KexAlgorithms/Ciphers/MACs/HostKeyAlgorithms when explicitly
# configured to allow them below (modern OpenSSH refuses to disable
# these, which is exactly why this needs an old base image).
FROM debian:stretch-slim

# stretch is archived: point apt at archive.debian.org or `apt-get update` fails with 404s
RUN sed -i 's|deb.debian.org|archive.debian.org|g; s|security.debian.org|archive.debian.org|g; /stretch-updates/d' /etc/apt/sources.list \
    && echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99archive

RUN apt-get update && apt-get install -y --no-install-recommends openssh-server \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir /var/run/sshd \
    && ssh-keygen -t dsa -f /etc/ssh/ssh_host_dsa_key -N "" \
    && ssh-keygen -t rsa -b 1024 -f /etc/ssh/ssh_host_rsa_key -N ""

COPY sshd_config /etc/ssh/sshd_config

# Test-only account; PasswordAuthentication is left on for local KEX probing
# convenience but the scanner itself never authenticates (see ssh_scanner.py).
RUN useradd -m -s /bin/bash scantest && echo "scantest:scantest" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
