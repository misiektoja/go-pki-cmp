# Image with the Insta Certifier CMP clients for the integration tests in this
# directory. The clients are proprietary and not distributed with this
# repository, so the build context is a local directory that holds them:
#
#   bin/cmpclient                          Certifier 10 cmpclient
#   bin/ssh-cmpclient                      Certifier 7 ssh-cmpclient, optional
#   lib/libssl.so.3, lib/libcrypto.so.3    OpenSSL from the same installation
#                                          as ssh-cmpclient, which needs it
#
# lib/ must exist even when it is empty. Both clients are linux/amd64
# binaries. Certifier 7 supports only Enterprise Linux 8 and ssh-cmpclient
# fails to load on Rocky Linux 9, which lacks libcrypt.so.1. The base image
# comes from rockylinux/rockylinux because the official rockylinux image stopped
# at 8.9. Build with make setup-certifier-clients.
FROM rockylinux/rockylinux:8-minimal@sha256:6d2ede107b4f005a638728711dae05d5fbbfd8abd521cecf5ab61196b361c965
RUN microdnf install -y libnsl && microdnf clean all
COPY bin/ /usr/local/certifier/bin/
COPY lib/ /usr/local/certifier/lib/
ENV PATH=/usr/local/certifier/bin:$PATH \
    LD_LIBRARY_PATH=/usr/local/certifier/lib
WORKDIR /work
