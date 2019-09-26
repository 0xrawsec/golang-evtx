MAIN_BASEN_SRC=evtxdump
RELEASE="$(GOPATH)/release/$(MAIN_BASEN_SRC)"
VERSION=v1.2.2
# Strips symbols and dwarf to make binary smaller
OPTS=-ldflags "-s -w"
ifdef DEBUG
	OPTS=
endif

all:
	$(MAKE) clean
	$(MAKE) init
	$(MAKE) compile

init:
	mkdir -p $(RELEASE)
	mkdir -p $(RELEASE)/linux
	mkdir -p $(RELEASE)/windows
	mkdir -p $(RELEASE)/darwin

compile:linux windows darwin

install:
	go install $(MAIN_BASEN_SRC).go

linux:
	GOARCH=386 GOOS=linux go build $(OPTS) -o $(RELEASE)/linux/$(MAIN_BASEN_SRC)-386 $(MAIN_BASEN_SRC).go
	GOARCH=amd64 GOOS=linux go build $(OPTS) -o $(RELEASE)/linux/$(MAIN_BASEN_SRC)-amd64 $(MAIN_BASEN_SRC).go
	cd $(RELEASE)/linux; shasum -a1 * > sha1.txt
	cd $(RELEASE)/linux; tar -cvzf ../$(MAIN_BASEN_SRC)-linux-$(VERSION).tar.gz *

windows:
	GOARCH=386 GOOS=windows go build $(OPTS) -o $(RELEASE)/windows/$(MAIN_BASEN_SRC)-386.exe $(MAIN_BASEN_SRC).go
	GOARCH=amd64 GOOS=windows go build $(OPTS) -o $(RELEASE)/windows/$(MAIN_BASEN_SRC)-amd64.exe $(MAIN_BASEN_SRC).go
	cd $(RELEASE)/windows; shasum -a1 * > sha1.txt
	cd $(RELEASE)/windows; tar -cvzf ../$(MAIN_BASEN_SRC)-windows-$(VERSION).tar.gz *

darwin:
	GOARCH=386 GOOS=darwin go build $(OPTS) -o $(RELEASE)/darwin/$(MAIN_BASEN_SRC)-386 $(MAIN_BASEN_SRC).go
	GOARCH=amd64 GOOS=darwin go build $(OPTS) -o $(RELEASE)/darwin/$(MAIN_BASEN_SRC)-amd64 $(MAIN_BASEN_SRC).go
	cd $(RELEASE)/darwin; shasum -a1 * > sha1.txt
	cd $(RELEASE)/darwin; tar -cvzf ../$(MAIN_BASEN_SRC)-darwin-$(VERSION).tar.gz *

clean:
	rm -rf $(RELEASE)/*
