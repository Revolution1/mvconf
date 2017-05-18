ROOT_DIR:=$(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

linux-bin:
	docker build -t mvconf-builder .
	mkdir -p $(ROOT_DIR)/bin
	docker run --rm -v $(ROOT_DIR)/mvconf:/root/mvconf -v $(ROOT_DIR)/bin/:/root/dist mvconf-builder \
	pyinstaller -F /root/mvconf/mvconf.py --paths=/root/mvconf
	docker image prune -f
