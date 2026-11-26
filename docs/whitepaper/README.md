# Sirus Technical White Paper

The compiled paper is [`sirus-whitepaper.pdf`](sirus-whitepaper.pdf).

Sources:

- `sirus-whitepaper.tex` — main document and preamble
- `sections/` — section and appendix sources
- `references.bib` — BibTeX references
- `Makefile` — reproducible build (`pdflatex`, `bibtex`, two more `pdflatex` passes)

Build:

```sh
make
```

Clean generated intermediate files:

```sh
make clean
```
