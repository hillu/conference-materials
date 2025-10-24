TARGETS := slides.reveal.html

all: $(TARGETS)
clean:
	rm -f $(TARGETS)
.PHONY: clean

%.svg: %.txt
	aasvg < $^ > $@.tmp
	mv $@.tmp $@

talk-url.png:
	qrencode https://hillu.github.io/conference-materials/hacklu-2025-build/slides.reveal.html -o $@

REVEALJS_URL ?= https://unpkg.com/reveal.js@4.6.1
# REVEALJS_URL ?= https://unpkg.com/reveal.js@^4
# REVEALJS_URL ?= $(CURDIR)/reveal.js

args += -V revealjs-url=$(REVEALJS_URL)
args += -V lang=de
args += -V theme=simple
args += -V fragments=false
args += --standalone
args += --embed-resources
args += --include-in-header=reveal-header.html
args += --lua-filter=svg-to-img.lua

slides.reveal.html: talk-url.png sourcegraph.svg sourcegraph2.svg

slides.reveal.html: slides.org
	pandoc --verbose -f org -t revealjs $(args) -i $< -o $@
