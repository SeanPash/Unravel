.PHONY: ui build test clean

# Build the React UI and copy the production bundle into the embed directory.
ui:
	npm --prefix ../ui install
	npm --prefix ../ui run build
	cp -r ../ui/dist/. internal/api/static/

# Full binary build: requires a prior 'make ui' or a previously built bundle.
build:
	go build -o engine ./cmd/engine

# Build the UI then the binary in one step.
release: ui build

test:
	go test ./...

clean:
	rm -f engine
	find internal/api/static -mindepth 1 ! -name '.gitkeep' ! -name '.gitignore' -delete
