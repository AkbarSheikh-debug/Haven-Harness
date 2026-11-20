# The Linux box test image: Rust (to build the helper), Node 24 (to run the tests), bubblewrap and perl (the box and a
# way to make raw system calls from inside it). Built by run-in-container.sh; nothing here is pulled at test time.
FROM rust:1-slim-bookworm
RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends bubblewrap perl netcat-openbsd wget ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=node:24-bookworm-slim /usr/local/ /usr/local/
RUN rm -f /usr/local/bin/yarn /usr/local/bin/yarnpkg && corepack enable
