TARGETS := slides.reveal.html

all: $(TARGETS)
clean:
	rm -f $(TARGETS)
.PHONY: clean

# pandoc default, can be overridden.
REVEALJS_URL ?= https://unpkg.com/reveal.js@^4/

slides.reveal.html: slides.org
	pandoc --verbose -f org -t revealjs \
		-V fragments=false \
		-V theme=simple \
		-V lang=en \
		-V $(REVEALJS_URL) \
		--include-in-header=reveal-header.html \
		--self-contained \
		-i $^ -o $@
