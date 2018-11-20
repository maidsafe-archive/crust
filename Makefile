SHELL:=/bin/bash
VERSION := $(shell cat Cargo.toml | grep "^version" | awk '{ print $$3 }' | sed 's/\"//g')
PWD := $(shell echo $$PWD)

build-container:
	docker rmi -f maidsafe/crust:${VERSION}
	docker build -t maidsafe/crust:${VERSION} .

push-container: build-container
	docker pull maidsafe/crust:${VERSION}

pull-container:
	docker push maidsafe/crust:${VERSION}

run-container-build: pull-container
	docker run --rm -v "${PWD}":/usr/src/crust maidsafe/crust:${VERSION}

run-container-build-debug: pull-container
	docker run --rm -it -v "${PWD}":/usr/src/crust maidsafe/crust:${VERSION} /bin/bash
