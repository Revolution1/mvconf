ROOT_DIR:=$(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

linux-bin:
	docker build -t mvconf-builder .
	mkdir -p $(ROOT_DIR)/bin
	docker run --rm -v $(ROOT_DIR)/src:/root/src -v $(ROOT_DIR)/bin/:/root/dist mvconf-builder \
	pyinstaller -F /root/src/mvconf.py --paths=/root/src
	docker image prune -f
