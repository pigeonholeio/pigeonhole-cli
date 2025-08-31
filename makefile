OPENAPI_PATH := "../server/src/docs/swagger.yaml"
SDK_PATH := /Users/rhysevans/git/pigeonhole/api

## help: Show this help
help:
	@echo "Available targets:"
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

generate-openapi-sdk:
	oapi-codegen -generate client -package sdk -o ${SDK_PATH}/client/client.gen.go ${OPENAPI_PATH}
	oapi-codegen -generate types -package sdk -o ${SDK_PATH}/types/types.gen.go ${OPENAPI_PATH}



secret-drop-file:
	go run main.go secret drop -r rhys@planesailing.io -f ~/Downloads/x.mp4

bump-tag:
	./bump-tag.sh
	
trigger-git:
	./bump-version.sh


git-push-all:
	git push --all -f -4
	git push --tags

goreleaser-release:
	GITLAB_TOKEN= goreleaser release --clean --fail-fast --auto-snapshot
	

release: trigger-git goreleaser-release
	
snapshot:
	GITLAB_TOKEN= goreleaser build --snapshot --clean


version: 
	./dist/default_darwin_amd64_v1/pigeonhole version


test-install:
	-brew update
	brew install pigeonhole-cli

install-deps:
	go install github.com/deepmap/oapi-codegen/v2/cmd/oapi-codegen@latest
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