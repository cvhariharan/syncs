FROM anchore/syft:v1.1.0 AS syft

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
FROM alpine:3.19.1

# install latest version of git, psql and jq
RUN apk upgrade && apk add --no-cache git postgresql-client jq

COPY --from=syft /syft /usr/local/bin/syft

RUN mkdir -p /syncer
COPY . /syncer/

LABEL com.mergestat.sync.clone="true"

ENTRYPOINT [ "/syncer/entrypoint.sh" ]
