generate-openapi-sdk:
	oapi-codegen -generate client -package sdk -o /Users/rhysevans/git/golangcliscaffold/sdk/client.gen.go /Users/rhysevans/git/pigeonholeapi-flask/pigeonhole/openapi.yaml
	oapi-codegen -generate types -package sdk -o /Users/rhysevans/git/golangcliscaffold/sdk/types.gen.go /Users/rhysevans/git/pigeonholeapi-flask/pigeonhole/openapi.yaml
	go build


secret-drop-file:
	go run main.go secret drop -r rhys.e@data-edge.co.uk -f ~/Downloads/x.mp4