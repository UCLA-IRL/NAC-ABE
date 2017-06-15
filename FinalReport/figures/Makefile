GRAFFLE_EXPORT = graffle2pdf
PDFCROP = pdfcrop

.PHONY: images

IMAGE_FILES=$(shell find . -name '*.graffle')

images: $(IMAGE_FILES:graffle=pdf)

%.pdf: %.graffle
	${GRAFFLE_EXPORT} $< $@
	${PDFCROP} $@ $@

clean:
	@echo rm -f $(IMAGE_FILES:graffle=pdf)
