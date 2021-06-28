######
## Stage 1: Clone the Git repository
######
FROM alpine/git as clone
WORKDIR /app
RUN git clone https://github.com/astryzia/BashScan.git

######
## Stage 2: Make final small image
######
FROM alpine

RUN apk add --update --no-cache && \
    apk add ca-certificates && \
    apk add arping && \
    apk add bc && \
    apk add bash && \
    rm -rf /var/cache/apk/*

WORKDIR /app

COPY --from=clone /app/BashScan/lib /app/lib
COPY --from=clone /app/BashScan/bashscan.sh /app/bashscan.sh
COPY --from=clone /app/BashScan/run.sh /app/run.sh
COPY --from=clone /app/BashScan/unify.sh /app/unify.sh

# Fix permissions and make sure that everything is run as a non-privileged user
RUN chmod +x *.sh lib/*.sh && \
    chown -R 1000:1000 /app
USER 1000:1000

ENV PATH=/app:$PATH

ENTRYPOINT ["/app/bashscan.sh"]
