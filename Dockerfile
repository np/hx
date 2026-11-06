# Build stage: compile hx with Stack against the pinned Stackage snapshot.
FROM debian:trixie AS build

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl build-essential git pkg-config \
      libgmp-dev libffi-dev zlib1g-dev libnuma-dev libsecp256k1-dev \
 && rm -rf /var/lib/apt/lists/*

RUN curl -sSL https://get.haskellstack.org/stable/linux-x86_64.tar.gz \
  | tar xz --wildcards --strip-components=1 -C /usr/local/bin '*/stack'

WORKDIR /hx
# Build the dependencies first so that they are cached between source edits.
COPY stack.yaml stack.yaml.lock hx.cabal ./
RUN stack setup && stack build --only-dependencies

COPY . .
RUN stack build --copy-bins --local-bin-path /usr/local/bin \
 && HX=/usr/local/bin/hx tests/run-tests.sh < /dev/null

# Runtime stage: just the binary and libsecp256k1.
FROM debian:trixie-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends libgmp10 libffi8 libsecp256k1-2 \
 && rm -rf /var/lib/apt/lists/*

COPY --from=build /usr/local/bin/hx /usr/local/bin/hx

ENTRYPOINT ["hx"]
CMD ["help"]
