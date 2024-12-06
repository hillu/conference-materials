TARGETS := slides.reveal.html

all: $(TARGETS)
clean:
	rm -f $(TARGETS)
.PHONY: clean

%.svg: %.txt
	aasvg < $^ > $@.tmp
	mv $@.tmp $@

talk-url.png:
	qrencode https://hillu.github.io/conference-materials/bsides-dd-2024/slides.reveal.html -o $@

REVEALJS_URL ?= https://unpkg.com/reveal.js@^4/
# REVEALJS_URL ?= $(CURDIR)/reveal.js

slides.reveal.html: slides.org
	pandoc --verbose -f org -t revealjs \
		-V fragments=false \
		-V theme=simple \
		-V lang=en \
		-V $(REVEALJS_URL) \
		--include-in-header=reveal-header.html \
		--self-contained \
		-i $^ -o $@
