SHELL:=/bin/bash
VERSION := $(shell cat Cargo.toml | grep "^version" | awk '{ print $$3 }' | sed 's/\"//g')
PWD := $(shell echo $$PWD)

build-container:
	rm -rf target/
	docker rmi -f maidsafe/crust:${VERSION}
	docker build -t maidsafe/crust:${VERSION} .

push-container:
	docker push maidsafe/crust:${VERSION}

run-container-build:
	docker run --rm -v "${PWD}":/usr/src/crust maidsafe/crust:${VERSION}

run-container-build-debug:
	docker run --rm -it -v "${PWD}":/usr/src/crust maidsafe/crust:${VERSION} /bin/bash
