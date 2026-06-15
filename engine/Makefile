.PHONY: ui build release test clean install

# Optional build-time Gemini key: read from the gitignored gemini.key file if it
# exists, with the trailing newline stripped (a stray newline would 401 against
# Gemini). Absent file -> empty key -> the binary falls back to the stub narrator.
# An explicit --gemini-key flag or GEMINI_API_KEY env still overrides it at runtime.
GEMINI_KEY := $(shell cat gemini.key 2>/dev/null | tr -d '\n')
LDFLAGS := -X 'main.embeddedGeminiKey=$(GEMINI_KEY)'

# Build the React UI and copy the production bundle into the embed directory.
ui:
	npm --prefix ../ui install
	npm --prefix ../ui run build
	cp -r ../ui/dist/. internal/api/static/

# Full binary build: requires a prior 'make ui' or a previously built bundle.
build:
	go build -ldflags "$(LDFLAGS)" -o unravel ./cmd/engine

# Build the UI then the binary in one step.
release: ui build

# Build the UI and binary, then install onto the user's PATH (no sudo). Depends on
# release (not just build) so a fresh clone gets the UI embedded in one command.
# Ensure ~/.local/bin is on PATH. To reinstall the binary only (e.g. after editing
# gemini.key), run `make build && cp unravel $(HOME)/.local/bin/`.
install: release
	mkdir -p $(HOME)/.local/bin
	cp unravel $(HOME)/.local/bin/unravel
	@echo "Installed to $(HOME)/.local/bin/unravel - ensure ~/.local/bin is on your PATH, then run: unravel"

test:
	go test ./...

clean:
	rm -f unravel
	find internal/api/static -mindepth 1 ! -name '.gitkeep' ! -name '.gitignore' -delete
