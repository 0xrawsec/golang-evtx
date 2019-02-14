FROM golang:alpine AS build-env
LABEL maintainer "Alexander Makhinov <monaxgt@gmail.com>" \
      repository="https://github.com/0xrawsec/golang-evtx"

COPY . /go/src/github.com/0xrawsec/golang-evtx

RUN apk add --no-cache git mercurial \
    && cd /go/src/github.com/0xrawsec/golang-evtx/tools/evtxdump \
    && go get -t . \
    && CGO_ENABLED=0 go build -ldflags="-s -w" \
                              -a \
                              -installsuffix static \
                              -o /evtxdump
RUN adduser -D app

FROM scratch

COPY --from=build-env /evtxdump /app/evtxdump
COPY --from=build-env /etc/passwd /etc/passwd

USER app

VOLUME /app/data

WORKDIR /app/data

ENTRYPOINT ["../evtxdump"]