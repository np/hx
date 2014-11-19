FROM quay.io/np__/haskell

MAINTAINER Nicolas Pouillard [https://nicolaspouillard.fr]

#RUN apt-get update && apt-get install ${OPTS_APT} git
ADD . /hx
WORKDIR /hx
RUN cabal update && cabal install
RUN curl -O cmdcheck https://github.com/np/cmdcheck/raw/master/cmdcheck
RUN ./cmdcheck tests/*.t
