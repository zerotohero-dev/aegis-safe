#
# .-'_.---._'-.
# ||####|(__)||   Protect your secrets, protect your business.
#   \\()|##//       Secure your sensitive data with Aegis.
#    \\ |#//                  <aegis.z2h.dev>
#     .\_/.
#

VERSION=0.12.0
PACKAGE=aegis-safe
REPO=z2hdev/aegis-safe
REPO_LOCAL="localhost:5000/aegis-safe"

all: build bundle push deploy

all-local: build bundle push-local deploy-local

build:
	go mod vendor
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

push-local:
	docker build . -t ${PACKAGE}:${VERSION}
	docker tag ${PACKAGE}:${VERSION} ${REPO_LOCAL}:${VERSION}
	docker push ${REPO_LOCAL}:${VERSION}

deploy:
	./hack/deploy.sh

deploy-local:
	./hack/deploy-local.sh

run-in-container:
	docker run ${PACKAGE}:${VERSION}
