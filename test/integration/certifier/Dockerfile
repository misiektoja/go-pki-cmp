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
# binaries. ssh-cmpclient is built for Enterprise Linux 8, which the base image
# matches. Build with make setup-certifier-clients.
FROM rockylinux:8-minimal@sha256:c584db6d77f40a71ab2364b55be18c154b8e92ba48189e2d82ba0aef64ffee32
RUN microdnf install -y libnsl && microdnf clean all
COPY bin/ /usr/local/certifier/bin/
COPY lib/ /usr/local/certifier/lib/
ENV PATH=/usr/local/certifier/bin:$PATH \
    LD_LIBRARY_PATH=/usr/local/certifier/lib
WORKDIR /work
