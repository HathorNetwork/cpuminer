FROM alpine:3.9 as builder

RUN set -x \
  && apk add --no-cache -t .build-deps \
         autoconf \
         automake \
         build-base \
         curl \
         curl-dev \
         git \
         openssl-dev

COPY . /tmp/cpuminer

RUN set -x \
  # Compile from source code.
  && cd /tmp/cpuminer \
  && ./autogen.sh \
  && ./configure CFLAGS="-O3 -march=native" \
  && make install

FROM alpine:3.9

RUN set -x \
  && apk add --no-cache \
         libcurl \
         libgcc \
         libstdc++ \
         openssl

COPY --from=builder /usr/local/bin/minerd /usr/local/bin/minerd

ENTRYPOINT ["minerd"]
