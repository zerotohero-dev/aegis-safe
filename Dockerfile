#
# .-'_.---._'-.
# ||####|(__)||   Protect your secrets, protect your business.
#   \\()|##//       Secure your sensitive data with Aegis.
#    \\ |#//                  <aegis.ist>
#     .\_/.
#

MAINTAINER Volkan Özçelik <volkan@aegis.ist>

# builder image
FROM golang:1.20.1-alpine3.17 as builder

RUN mkdir /build
COPY cmd /build/cmd
COPY internal /build/internal
COPY vendor /build/vendor
COPY go.mod /build/go.mod
WORKDIR /build
RUN CGO_ENABLED=0 GOOS=linux go build -mod vendor -a -o aegis-safe ./cmd/main.go

# generate clean, final image for end users
FROM gcr.io/distroless/static-debian11

LABEL "maintainers"="Volkan Özçelik <volkan@aegis.ist>"
LABEL "version"="1.3.0"
LABEL "website"="https://aegis.ist/"
LABEL "repo"="https://github.com/zerotohero-dev/aegis-safe"
LABEL "documentation"="https://aegis.ist/docs/"
LABEL "contact"="https://aegis.ist/contact/"
LABEL "community"="https://aegis.ist/contact/#community"
LABEL "changelog"="https://aegis.ist/changelog"

COPY --from=builder /build/aegis-safe .

# executable
ENTRYPOINT [ "./aegis-safe" ]
CMD [ "" ]
