
SHELL := /bin/bash

# The name of the executable (default is current directory name)
#TARGET := $(shell echo $${PWD\#\#*/})
#.DEFAULT_GOAL: $(TARGET)

# These will be provided to the target
#VERSION := 1.0.0
#VERSION          := $(shell git describe --tags --always --dirty="-dev")
#DATE             := $(shell date -u '+%Y-%m-%d-%H%M UTC')
#VERSION_FLAGS    := -ldflags='-X "main.Version=$(VERSION)" -X "main.BuildTime=$(DATE)"'
#BUILD := `git rev-parse HEAD`

# Use linker flags to provide version/build settings to the target
#LDFLAGS=-ldflags "-X=main.Version=$(VERSION) -X=main.Build=$(BUILD)"

# go source files, ignore vendor directory
SRC = $(shell find . -type f -name '*.go' -not -path "./internal/protogen/*")
SRCPROTO = $(shell find . -type f -name '*.proto'")
MFILE = cmd/main.go
EXEC = cmd/cdcsa
MFILEP = cmd/partyserver/partyserver.go
EXECP = cmd/partyserver/partysrv
MFILEU = cmd/userserver/userserver.go
EXECU = cmd/userserver/usersrv
MFILEW = cmd/userworker/main.go
EXECW = cmd/userworker/worksrv


PKGS = $(go list ./... | grep -v /proto/ | grep -v /protogen/)

.PHONY: all chk lint proto build test clean fmt gocritic staticcheck errcheck revive golangcilint protofmt protolint tidy pkgupd run runp runu runw runprod doc

all: chk protoc buildp

chk: goimports fmt gocritic staticcheck errcheck protofmt protolint

rev: revive

lint: golangcilint
 
#protoc:
#  protoc \
#    --go_out=. \
#    --go_opt=module=github.com/prov100/dc1 \
#    $(SRCPROTO)


build: 
	@echo "Building dc1"	
	@go build -o $(EXEC) $(MFILE)
	@go build -o $(EXECP) $(MFILEP)
	@go build -o $(EXECU) $(MFILEU)
	@go build -o $(EXECW) $(MFILEW)

test:
	@mysql -uroot -p$(SC_DCSA_DBPASSROOT) -e 'DROP DATABASE IF EXISTS  $(SC_DCSA_DBNAME_TEST);'
	@mysql -uroot -p$(SC_DCSA_DBPASSROOT) -e 'CREATE DATABASE $(SC_DCSA_DBNAME_TEST);'
	@mysql -uroot -p$(SC_DCSA_DBPASSROOT) -e "GRANT ALL ON *.* TO '$(SC_DCSA_DBUSER_TEST)'@'$(SC_DCSA_DBHOST)';"
	@mysql -uroot -p$(SC_DCSA_DBPASSROOT) -e 'FLUSH PRIVILEGES;'
	@mysql -u$(SC_DCSA_DBUSER_TEST) -p$(SC_DCSA_DBPASS_TEST) $(SC_DCSA_DBNAME_TEST) < sql/mysql/sc_dcsa_mysql_schema.sql

	#@mysql -uroot -p$(SC_DCSA_DBPASSROOT) --host=localhost --port=3201 -e 'DROP DATABASE IF EXISTS  $(SC_DCSA_DBNAME_TEST);'
	#@mysql -uroot -p$(SC_DCSA_DBPASSROOT) --host=localhost --port=3201 -e 'CREATE DATABASE $(SC_DCSA_DBNAME_TEST);'
	#@mysql -uroot -p$(SC_DCSA_DBPASSROOT) --host=localhost --port=3201 -e "GRANT ALL ON *.* TO '$(SC_DCSA_DBUSER_TEST)'@'$(SC_DCSA_DBHOST)';"
	#@mysql -uroot -p$(SC_DCSA_DBPASSROOT) --host=localhost --port=3201 -e 'FLUSH PRIVILEGES;'
	#@mysql -u$(SC_DCSA_DBUSER_TEST) -p$(SC_DCSA_DBPASS_TEST) -host=localhost --port=3201 $(SC_DCSA_DBNAME_TEST) < sql/mysql/sc_dcsa_mysql_schema.sql


	@echo "Starting tests"
	go test -v github.com/prov100/dc1/internal/controllers/partycontrollers
	#@for pkg in $$(go list ./...); do echo "Testing" $$pkg && go test -v $$pkg; done		

clean:
	@rm -f $(EXEC)

goimports:
	@echo "Running goimports"		
	@goimports -l -w $(SRC)

fmt:
	@echo "Running gofumpt"
	@gofumpt -l -w .
	@echo "Running gofmt"		
	@gofmt -s -l -w $(SRC)

gocritic:
	@echo "Running gocritic"
	@gocritic check $(SRC)

staticcheck:
	@echo "Running staticcheck"
	@staticcheck ./...

errcheck:
	@echo "Running errcheck"
	@errcheck ./...

revive:
	@echo "Running revive"
	@revive $(SRC)

golangcilint:
	@echo "Running golangci-lint"
	@golangci-lint run

protofmt:
	@echo "Running protofmt"
	cd internal/proto && buf format -w

protolint:
	@echo "Running protolint"
	@buf lint

tidy:
	go mod tidy -v -e

pkgupd:
	go get -u ./...
	go mod tidy -v -e

run:
	@echo "Starting dc1"	
	@./$(EXEC) --dev 

runp:
	@echo "Starting dc1 partyserver"	
	@./$(EXECP) --dev 

runu: build
	@echo "Starting dc1 userserver"	
	@./$(EXECU) --dev 

runw: build
	@echo "Starting dc1 worker server"	
	@./$(EXECW) --dev 


runprod:	
	@echo "Starting dc1"	
	@./$(EXEC) 

doc: 

