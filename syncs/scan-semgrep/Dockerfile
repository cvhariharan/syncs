FROM semgrep/semgrep:1.68.0

RUN apk update && apk add git postgresql-client jq

RUN mkdir -p /syncer
COPY schema.sql entrypoint.sh /syncer

RUN chmod +x /syncer/entrypoint.sh

LABEL com.mergestat.sync.clone="true"

WORKDIR /mergestat/repo

# Add semgrep rules
RUN git clone https://github.com/semgrep/semgrep-rules.git /syncer/semgrep-rules/official
RUN rm -r /syncer/semgrep-rules/official/.github /syncer/semgrep-rules/official/stats
RUN find /syncer/semgrep-rules/official -maxdepth 1 -type f -delete

RUN git clone https://github.com/trailofbits/semgrep-rules.git /syncer/semgrep-rules/trailofbits
RUN rm -r /syncer/semgrep-rules/trailofbits/.github
RUN find /syncer/semgrep-rules/trailofbits -maxdepth 1 -type f -delete

RUN git clone https://github.com/frappe/semgrep-rules.git /syncer/semgrep-rules/frappe
RUN rm -r /syncer/semgrep-rules/frappe/.github
RUN find /syncer/semgrep-rules/frappe -maxdepth 1 -type f -delete

RUN git clone https://github.com/0xdea/semgrep-rules.git /syncer/semgrep-rules/generic

ENTRYPOINT [ "/syncer/entrypoint.sh" ]