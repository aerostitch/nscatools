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
	go test $(GO_EXTRAFLAGS) -v -bench=. -benchmem -cpuprofile=cpu.prof -memprofile=mem.prof ./...
	go tool pprof -top -lines -nodecount=25 nscatools.test cpu.prof
	go tool pprof -text -lines -nodecount=25 -alloc_space nscatools.test mem.prof
	go tool pprof -text -lines -nodecount=25 -alloc_objects nscatools.test mem.prof

gocov:
	gocov test | gocov report
	# gocov test >/tmp/gocovtest.json ; gocov annotate /tmp/gocovtest.json

install: test
	go clean -v github.com/tubemogul/nscatools
	go install github.com/tubemogul/nscatools
