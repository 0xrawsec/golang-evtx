MAIN_BASEN_SRC=evtxmon
RELEASE="$(GOPATH)/release/$(MAIN_BASEN_SRC)"
VERSION=v1.2.4
COMMITID=$(shell git rev-parse HEAD)
# Strips symbols and dwarf to make binary smaller
OPTS=-trimpath -ldflags "-s -w"
ifdef DEBUG
	OPTS=
endif

all:
	$(MAKE) clean
	$(MAKE) init
	$(MAKE) compile

init: buildversion
	mkdir -p $(RELEASE)
	mkdir -p $(RELEASE)/linux
	mkdir -p $(RELEASE)/windows
	mkdir -p $(RELEASE)/darwin

compile: windows
	
install:
	go install ./

buildversion:
	printf "package main\n\nconst(\n    Version=\"$(VERSION)\"\n    CommitID=\"$(COMMITID)\"\n)\n" > version.go

linux:
	GOARCH=386 GOOS=linux go build $(OPTS) -o $(RELEASE)/linux/$(MAIN_BASEN_SRC)-386 ./
	GOARCH=amd64 GOOS=linux go build $(OPTS) -o $(RELEASE)/linux/$(MAIN_BASEN_SRC)-amd64 ./
	cd $(RELEASE)/linux; shasum -a1 * > sha1.txt
	cd $(RELEASE)/linux; tar -cvzf ../$(MAIN_BASEN_SRC)-linux-$(VERSION).tar.gz *

windows:
	GOARCH=386 GOOS=windows go build $(OPTS) -o $(RELEASE)/windows/$(MAIN_BASEN_SRC)-386.exe ./
	GOARCH=amd64 GOOS=windows go build $(OPTS) -o $(RELEASE)/windows/$(MAIN_BASEN_SRC)-amd64.exe ./
	cd $(RELEASE)/windows; shasum -a1 * > sha1.txt
	cd $(RELEASE)/windows; tar -cvzf ../$(MAIN_BASEN_SRC)-windows-$(VERSION).tar.gz *

darwin:
	GOARCH=386 GOOS=darwin go build $(OPTS) -o $(RELEASE)/darwin/$(MAIN_BASEN_SRC)-386 ./
	GOARCH=amd64 GOOS=darwin go build $(OPTS) -o $(RELEASE)/darwin/$(MAIN_BASEN_SRC)-amd64 ./
	cd $(RELEASE)/darwin; shasum -a1 * > sha1.txt
	cd $(RELEASE)/darwin; tar -cvzf ../$(MAIN_BASEN_SRC)-darwin-$(VERSION).tar.gz *

clean:
	rm -rf $(RELEASE)/*
