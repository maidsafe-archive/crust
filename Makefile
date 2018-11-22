SHELL:=/bin/bash
VERSION := $(shell cat Cargo.toml | grep "^version" | awk '{ print $$3 }' | sed 's/\"//g')
PWD := $(shell echo $$PWD)

build-container:
	docker rmi -f maidsafe/crust:${VERSION}
	docker build -t maidsafe/crust:${VERSION} .

push-container: build-container
	docker push maidsafe/crust:${VERSION}

run-container-build: build-container
	docker run --rm -v "${PWD}":/usr/src/crust maidsafe/crust:${VERSION}

run-container-build-debug: build-container
	docker run --rm -it -v "${PWD}":/usr/src/crust maidsafe/crust:${VERSION} /bin/bash
