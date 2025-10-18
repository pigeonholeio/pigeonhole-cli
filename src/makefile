login:
	go run main.go login --verbose
login-github:
	go run main.go login --provider github --verbose
login-gitlab:
	go run main.go login --provider gitlab --verbose


https://sts.windows.net/02686153-276f-4f53-886b-14226cd70045/.well-known/openid-configuration
update-go:

	go clean -modcache
	rm -rf $(go env GOMODCACHE)/github.com/pigeonholeio/common@*
	go get github.com/pigeonholeio/common@latest
	go mod tidy 
	go mod vendor
list-secret:
	go run main.go s ls --all
send-secret:
	go run main.go s s -r rhys.evans@darkskope.com -f ../renovate.log -e -1

activate-rhysevans:
	cp ~/.pigeonhole/config.yaml ~/.pigeonhole/config-rhysevans.yaml
activate-alertspeed:
	cp ~/.pigeonhole/config-alertspeed.yaml ~/.pigeonhole/config-alertspeed.yaml

post-secret-test:
	go run main.go s s -r rhys@rhysevans.co.uk -f ./vendor
	go run main.go s s -r rhys@rhysevans.co.uk -f ./vendor
	go run main.go s s -r rhys@rhysevans.co.uk -f ./vendor
	go run main.go s s -r rhys@rhysevans.co.uk -f ./vendor
	go run main.go s s -r rhys@rhysevans.co.uk -f ./vendor
	go run main.go s s -r rhys@rhysevans.co.uk -f ./vendor
	go run main.go s s -r rhys@rhysevans.co.uk -f ./vendor
	go run main.go s s -r rhys@rhysevans.co.uk -f ./vendor
	go run main.go s s -r rhys@rhysevans.co.uk -f ./vendor
	go run main.go s s -r rhys@rhysevans.co.uk -f ./vendor
	go run main.go s s -r rhys@rhysevans.co.uk -f ./vendor
	go run main.go s s -r rhys@rhysevans.co.uk -f ./vendor
	go run main.go s s -r rhys@rhysevans.co.uk -f ./vendor

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

