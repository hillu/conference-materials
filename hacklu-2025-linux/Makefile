TARGETS := slides.reveal.html

all: $(TARGETS)
clean:
	rm -f $(TARGETS)
.PHONY: clean

%.svg: %.txt
	aasvg < $^ > $@.tmp
	mv $@.tmp $@

talk-url.png:
	qrencode https://hillu.github.io/conference-materials/hacklu-2025-linux/slides.reveal.html -o $@

REVEALJS_URL ?= https://unpkg.com/reveal.js@4.6.1
# REVEALJS_URL ?= https://unpkg.com/reveal.js@^4
# REVEALJS_URL ?= $(CURDIR)/reveal.js

args += -V revealjs-url=$(REVEALJS_URL)
args += -V lang=en
# args += -V theme=simple
args += --standalone
args += --embed-resources
args += --include-in-header=reveal-header.html
args += --lua-filter=svg-to-img.lua

slides.reveal.html: audit-laurel.svg laurel.svg velo.svg hierarchy.png velo-laurel-siem-soar.svg velo-artifacts.svg \
	reveal-header.html master-minion.svg talk-url.png

slides.reveal.html: slides.md
	pandoc --verbose -f markdown -t revealjs $(args) -i $< -o $@
