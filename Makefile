SHELL:=/bin/bash
VERSION := $(shell cat Cargo.toml | grep "^version" | awk '{ print $$3 }' | sed 's/\"//g')
PWD := $(shell echo $$PWD)

build-container:
	docker rmi jacderida/crust:${VERSION}
	docker build -t jacderida/crust:${VERSION} .

push-container: build-container
	docker push jacderida/crust:${VERSION}

run-container-build:
	docker run --rm -v "${PWD}":/usr/src/crust jacderida/crust:${VERSION}
