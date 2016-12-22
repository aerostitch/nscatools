.PHONY: all

all: test race bench
 
test: fmt lint vet
	go test $(GO_EXTRAFLAGS) -v -cover -covermode=count ./...

lint:
	golint $(GO_EXTRAFLAGS) -set_exit_status

fmt:
	@if [ -n "`gofmt -l .`" ]; then \
	 	printf >&2 'Some files are not in the gofmt format. Please fix.'; \
 		exit 1; \
	fi

vet:
	go tool vet -v *.go

race:
	go test $(GO_EXTRAFLAGS) -v -race ./...

bench:
	go test $(GO_EXTRAFLAGS) -v -bench=. -benchmem ./...

gocov:
	gocov test | gocov report

install: test
	go clean -v github.com/tubemogul/nscatools
	go install github.com/tubemogul/nscatools
