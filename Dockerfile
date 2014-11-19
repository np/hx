FROM quay.io/np__/haskell

MAINTAINER Nicolas Pouillard [https://nicolaspouillard.fr]

ADD https://github.com/np/cmdcheck/raw/master/cmdcheck /usr/bin/cmdcheck
RUN cabal update && cabal install haskoin base16-bytestring scientific binary RFC1751 aeson

ADD   . /hx
WORKDIR /hx
RUN     cabal install
#RUN     chmod +x /usr/bin/cmdcheck && /usr/bin/cmdcheck tests/*.t
#RUN apt-get update && apt-get install ${OPTS_APT} lib-ghc...
