TARGETS := slides.reveal.html

all: $(TARGETS)
clean:
	rm -f $(TARGETS)
.PHONY: clean

%.svg: %.txt
	aasvg < $^ > $@.tmp
	mv $@.tmp $@

talk-url.svg:
	qrencode --type=SVG --foreground=ffffffff --background=00000000 https://hillu.github.io/conference-materials/balccon-2k26/slides.reveal.html -o $@
project-url.svg:
	qrencode --type=SVG --foreground=ffffffff --background=00000000 https://codeberg.org/hillu/rk-expose -o $@


# REVEALJS_URL ?= https://unpkg.com/reveal.js@4.6.1
# REVEALJS_URL ?= https://unpkg.com/reveal.js@^4
REVEALJS_URL ?= $(CURDIR)/reveal.js-4.6.1

args += -V revealjs-url=$(REVEALJS_URL)
args += -V lang=en
args += -V theme=night
args += -V fragments=false
args += --standalone
args += --embed-resources
args += --include-in-header=reveal-header.html
args += --lua-filter=svg-to-img.lua

slides.reveal.html: talk-url.svg project-url.svg getdents-1a.svg getdents-2a.svg

slides.reveal.html: slides.org
	pandoc --verbose -f org -t revealjs $(args) -i $< -o $@
