.PHONY: proto test

proto:
#	protoc --proto_path=proto --go_out=pkg/message --go_opt=paths=source_relative proto/*.proto
	cd proto && protoc --go_out=../pkg/message --go_opt=paths=import --go-grpc_out=../pkg/message --go-grpc_opt=paths=import *.proto
#	protoc --go_out=pkg/message --go-grpc_out=pkg/message proto/*.proto

test: proto
	go test -cover -race ./...

clean:
	rm -rf pkg/message/*
