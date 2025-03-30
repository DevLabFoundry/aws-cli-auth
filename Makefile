OWNER := DevLabFoundry
NAME := aws-cli-auth
GIT_TAG := 0.11.11
VERSION := v$(GIT_TAG)
REVISION := aaaabbbbb1234

LDFLAGS := -ldflags="-s -w -X \"github.com/$(OWNER)/$(NAME)/cmd.Version=$(VERSION)\" -X \"github.com/$(OWNER)/$(NAME)/cmd.Revision=$(REVISION)\" -extldflags -static"

.PHONY: test test_ci tidy install buildprep build buildmac buildwin

test: test_prereq
	go test ./... -v -mod=readonly -coverprofile=.coverage/out -race | tee .coverage/test.out ; \
	cat .coverage/test.out | go-junit-report > .coverage/report-junit.xml ; \
	gocov convert .coverage/out | gocov-xml > .coverage/report-cobertura.xml

test_ci:
	go test ./... -mod=readonly

test_prereq: 
	mkdir -p .coverage
	go install github.com/jstemmer/go-junit-report@v0.9.1 && \
	go install github.com/axw/gocov/gocov@v1.0.0 && \
	go install github.com/AlekSi/gocov-xml@v1.0.0

install:
	go mod tidy

.PHONY: clean
clean:
	rm -rf bin/*
	rm -rf dist/*
	rm -rf vendor/*

.PHONY: cross-build

build-win: 
	for arch in amd64 386; do \
		GOOS=windows GOARCH=$$arch CGO_ENABLED=0 go build -mod=readonly -buildvcs=false $(LDFLAGS) -o dist/$(NAME)-windows-$$arch .; \
	done

cross-build: build-win
	for os in darwin linux; do \
		GOOS=$$os CGO_ENABLED=0 go build -mod=readonly -buildvcs=false $(LDFLAGS) -o dist/$(NAME)-$$os .; \
	done

release:
	OWNER=$(OWNER) NAME=$(NAME) PAT=$(PAT) VERSION=$(VERSION) . hack/release.sh 

tag: 
	git tag -a $(VERSION) -m "ci tag release" $(REVISION)
	git push origin $(VERSION)

tagbuildrelease: tag cross-build release

show_coverage: test
	go tool cover -html=.coverage/out

.PHONY: deps
deps:
	GO111MODULE=on go mod vendor

.PHONY: dist
dist:
	cd dist && \
	$(DIST_DIRS) cp ../LICENSE {} \; && \
	$(DIST_DIRS) cp ../README.md {} \; && \
	$(DIST_DIRS) tar -zcf $(NAME)-$(VERSION)-{}.tar.gz {} \; && \
	$(DIST_DIRS) zip -r $(NAME)-$(VERSION)-{}.zip {} \; && \
	cd ..
