FROM quay.io/np__/haskell

MAINTAINER Nicolas Pouillard [https://nicolaspouillard.fr]

RUN cabal update && cabal install haskoin base16-bytestring scientific binary RFC1751 aeson

ADD   . /hx
WORKDIR /hx
RUN     cabal install
ADD     https://github.com/np/cmdcheck/raw/master/cmdcheck /hx/cmdcheck
RUN     PATH=/hx/dist/build/hx:$PATH \
          bash -e /hx/cmdcheck tests/*.t || echo "Tests failed!"
#RUN apt-get update && apt-get install ${OPTS_APT} lib-ghc...
