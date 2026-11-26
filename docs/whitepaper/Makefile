LATEX ?= pdflatex
BIBTEX ?= bibtex

.PHONY: all clean

all: sirus-whitepaper.pdf

sirus-whitepaper.pdf: sirus-whitepaper.tex references.bib $(wildcard sections/*.tex)
	$(LATEX) -interaction=nonstopmode -halt-on-error sirus-whitepaper.tex
	$(BIBTEX) sirus-whitepaper
	$(LATEX) -interaction=nonstopmode -halt-on-error sirus-whitepaper.tex
	$(LATEX) -interaction=nonstopmode -halt-on-error sirus-whitepaper.tex

clean:
	rm -f *.aux *.bbl *.blg *.log *.out *.toc *.lof *.lot *.pdf
