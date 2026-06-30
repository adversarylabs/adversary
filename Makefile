BINARY := bin/adversary

.PHONY: build test clean

build:
	mkdir -p $(dir $(BINARY))
	go build -o $(BINARY) .

test:
	go test ./...

clean:
	rm -f $(BINARY)
