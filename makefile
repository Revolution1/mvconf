ROOT_DIR:=$(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

linux-bin:
	docker build -t mvconf-builder .
	mkdir -p $(ROOT_DIR)/bin
	docker run --rm -it -v $(ROOT_DIR)/src:/root/src -v $(ROOT_DIR)/bin:/root/bin mvconf-builder
	docker image prune -f
