OPENAPI_PATH := "../server/src/docs/swagger.yaml"
SDK_PATH := /Users/rhysevans/git/pigeonhole/api

## help: Show this help
help:
	@echo "Available targets:"
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

generate-openapi-sdk:
	oapi-codegen -generate client -package sdk -o ${SDK_PATH}/client/client.gen.go ${OPENAPI_PATH}
	oapi-codegen -generate types -package sdk -o ${SDK_PATH}/types/types.gen.go ${OPENAPI_PATH}


	
trigger-git:
	./bump-version.sh


git-push-all:
	git push --all -f -4
	git push --tags

goreleaser-release:
	GITLAB_TOKEN= goreleaser release --clean --fail-fast --auto-snapshot
	


	
snapshot:
	GITLAB_TOKEN= goreleaser build --snapshot --clean


XVERSION := $(shell git tag | sort -r -V | head -n 1)
version:
	@echo $(XVERSION)

test-install:
	-brew update
	brew install pigeonhole-cli

install-deps:
	go install github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@latest
	brew install goreleaser kubectl helm yq

.PHONY: gen-files

gen-files:
	dd if=/dev/urandom of=file_10MB.bin bs=1M count=10 status=none
	dd if=/dev/urandom of=file_100MB.bin bs=1M count=100 status=none
	dd if=/dev/urandom of=file_1024MB.bin bs=1M count=1024 status=none



push-workflow:
	git pull
	echo "#" >> src/trigger.yml
	git add .circleci src
	git commit -m'trigger workflow'
	git push


test-github:
	curl -XPOST -d localhost:3000/v1/auth/oidc/handler/github

# update-go:
# 	cd src && go get -u 
# all && go mod tidy && go mod vendor
# 	cd src && go get -u && go mod vendor



# all: build-deb build-rpm build-choco sign-all
build-deb-releaser:
	@echo "==> Building Deb releaser"
	@docker build --no-cache -t pigeonhole-cli-releaser-deb:latest -f build/deb.Dockerfile .
build-rpm-releaser:
	@echo "==> Building Rpm releaser"
	@docker build --no-cache -t pigeonhole-cli-releaser-rpm:latest -f build/rpm.Dockerfile .

run_repo_deb: 
	docker run -it --rm \
		--env "XVERSION=$(XVERSION)" \
		-v $$(realpath ~/.gnupg):/root/.gnupgx \
		-v $$(realpath ~/.gitconfig):/root/.gitconfig \
		-v $$(realpath ~/.ssh):/root/.ssh:ro \
		-v ./dist:/dist:ro \
		-v /Users/rhysevans/git/pigeonhole/repo:/repo \
		-v ./build/makefile:/app/makefile \
		pigeonhole-cli-releaser-deb:latest

# run_repo_rpm:
# 	docker run -it --rm \
# 		--env "XVERSION=$(XVERSION)" \
# 		-v $$(realpath ~/.gnupg):/root/.gnupgx \
# 		-v $$(realpath ~/.gitconfig):/root/.gitconfig \
# 		-v $$(realpath ~/.ssh):/root/.ssh:ro \
# 		-v ./dist:/dist:ro \
# 		-v /Users/rhysevans/git/pigeonhole/repo:/repo \
# 		-v ./build/makefile:/app/makefile \
# 		pigeonhole-cli-releaser-rpm:latest



build-deb: 
	@echo "==> Building Deb package"
	@docker run -it --rm \
		--env "XVERSION=$(XVERSION)" \
		-v $$(realpath ~/.gnupg):/root/.gnupgx \
		-v $$(realpath ~/.gitconfig):/root/.gitconfig \
		-v $$(realpath ~/.ssh):/root/.ssh:ro \
		-v ./dist:/dist:ro \
		-v /Users/rhysevans/git/pigeonhole/repo:/repo \
		-v ./build/makefile:/app/makefile \
		pigeonhole-cli-releaser-deb:latest make build-deb

build-rpm: 
	@echo "==> Building RPM package"
	@docker run -it --rm \
		--env "XVERSION=$(XVERSION)" \
		-v $$(realpath ~/.gnupg):/root/.gnupgx \
		-v $$(realpath ~/.gitconfig):/root/.gitconfig \
		-v $$(realpath ~/.ssh):/root/.ssh:ro \
		-v ./dist:/dist:ro \
		-v /Users/rhysevans/git/pigeonhole/repo:/repo \
		-v ./build/makefile:/app/makefile \
		pigeonhole-cli-releaser-rpm:latest make build-rpm

full-release-packages: build-rpm-releaser build-deb-releaser build-deb build-rpm
push-repo:
	cd ../repo && git add . && git commit -m"Release $(XVERSION)" && git push
release-packages: build-deb build-rpm push-repo
# curl -s https://packages.pigeono.io/gpg.pub --output - > /etc/apt/trusted.gpg.d/pigeonholeio.gpg

release: trigger-git goreleaser-release release-packages