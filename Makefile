all: lint vet test getkeys getsamplemar testparser

lint:
	golint go.mozilla.org/mar

vet:
	go vet go.mozilla.org/mar

test:
	go test go.mozilla.org/mar

getkeys:
	# only sync firefox keys every day max
	find firefoxkeys.go -mtime 7 -exec bash get_firefox_keys.sh \;

getsamplemar:
	@if [ ! -e firefox-60.0esr-60.0.1esr.partial.mar ]; then \
		wget http://download.cdn.mozilla.net/pub/firefox/releases/60.0.1esr/update/win64/en-US/firefox-60.0esr-60.0.1esr.partial.mar ;\
	fi

testparser:
	go run examples/parse.go firefox-60.0esr-60.0.1esr.partial.mar 2>&1 | grep 'signature: OK, valid signature from release1_sha384'

