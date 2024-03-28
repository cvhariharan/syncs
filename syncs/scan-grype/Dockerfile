FROM anchore/grype:v0.74.7 AS grype

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
FROM alpine:3.19.1

# install latest version of git, psql and jq
RUN apk upgrade && apk add --no-cache git postgresql-client jq

COPY --from=grype /grype /usr/local/bin/grype

RUN mkdir -p /syncer
COPY . /syncer/

LABEL com.mergestat.sync.clone="true"

ENTRYPOINT [ "/syncer/entrypoint.sh" ]
