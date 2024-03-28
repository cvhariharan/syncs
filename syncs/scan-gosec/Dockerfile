FROM golang:1.22.1-alpine3.19

# install latest version of psql and jq
RUN apk upgrade && apk add --no-cache curl postgresql-client jq

# install gosec binary to /usr/local/bin
# TODO(@riyaz): remove script piping and do manual checksum verification
RUN curl -sfL https://raw.githubusercontent.com/securego/gosec/master/install.sh | sh -s - -b /usr/local/bin v2.19.0

COPY . /syncer/
LABEL com.mergestat.sync.clone="true"


ENTRYPOINT [ "/syncer/entrypoint.sh" ]
