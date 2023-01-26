#
# .-'_.---._'-.
# ||####|(__)||   Protect your secrets, protect your business.
#   \\()|##//       Secure your sensitive data with Aegis.
#    \\ |#//                  <aegis.z2h.dev>
#     .\_/.
#

VERSION=0.10.0
PACKAGE=aegis-safe
REPO=z2hdev/aegis-safe

all: build bundle push deploy

build:
	go build -o ${PACKAGE} ./cmd/main.go

run:
	./hack/run.sh

bundle:
	go mod vendor
	docker build . -t ${PACKAGE}:${VERSION}

push:
	docker build . -t ${PACKAGE}:${VERSION}
	docker tag ${PACKAGE}:${VERSION} ${REPO}:${VERSION}
	docker push ${REPO}:${VERSION}

deploy:
	./hack/deploy.sh

run-in-container:
	docker run ${PACKAGE}:${VERSION}
