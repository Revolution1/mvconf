ROOT_DIR:=$(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

linux-bin:
	docker build -t mvconf-builder .
	mkdir -p $(ROOT_DIR)/bin /tmp/mvconf-dist
	docker run --rm -it -v $(ROOT_DIR)/src:/root/src -v /tmp/mvconf-dist:/root/dist mvconf-builder \
	pyinstaller -F /root/src/mvconf.py --paths=/root/src
	mv /tmp/mvconf-dist/* $(ROOT_DIR)/bin/
	docker image prune -f
