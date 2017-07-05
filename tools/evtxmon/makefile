RELEASE="release"
MAIN_BASEN_SRC=evtxmon
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

linux:
	GOARCH=386 GOOS=linux go build $(OPTS) -o $(RELEASE)/linux/$(MAIN_BASEN_SRC)-386 $(MAIN_BASEN_SRC).go
	GOARCH=amd64 GOOS=linux go build $(OPTS) -o $(RELEASE)/linux/$(MAIN_BASEN_SRC)-amd64 $(MAIN_BASEN_SRC).go

windows:
	GOARCH=386 GOOS=windows go build $(OPTS) -o $(RELEASE)/windows/$(MAIN_BASEN_SRC)-386.exe $(MAIN_BASEN_SRC).go
	GOARCH=amd64 GOOS=windows go build $(OPTS) -o $(RELEASE)/windows/$(MAIN_BASEN_SRC)-amd64.exe $(MAIN_BASEN_SRC).go

darwin:
	GOARCH=386 GOOS=darwin go build $(OPTS) -o $(RELEASE)/darwin/$(MAIN_BASEN_SRC)-386 $(MAIN_BASEN_SRC).go
	GOARCH=amd64 GOOS=darwin go build $(OPTS) -o $(RELEASE)/darwin/$(MAIN_BASEN_SRC)-amd64 $(MAIN_BASEN_SRC).go

clean:
	rm -rf $(RELEASE)/*
