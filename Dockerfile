FROM quay.io/np__/haskell

MAINTAINER Nicolas Pouillard [https://nicolaspouillard.fr]

RUN cabal update && cabal install haskoin base16-bytestring scientific binary RFC1751 aeson

ADD   . /hx
WORKDIR /hx
RUN     cabal install
ADD     https://github.com/np/cmdcheck/raw/master/cmdcheck /hx/cmdcheck
RUN     chmod +x /hx/cmdcheck && \
        PATH=/hx/dist/build/hx:$PATH \
          /hx/cmdcheck tests/*.t
#RUN apt-get update && apt-get install ${OPTS_APT} lib-ghc...
