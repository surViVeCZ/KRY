
SHELL := /bin/bash

TYPE ?= c
PORT ?= 5555
build:
	( \
		python3 -m venv venv; \
		source venv/bin/activate; \
		pip3 install -r requirements.txt \
    )

run:
	( \
       source venv/bin/activate; \
       python3 kry.py $(TYPE) $(PORT) \
    )

clean:
	rm -rf venv
