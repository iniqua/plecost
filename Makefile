.PHONY: deps
deps:
	pip install -U -r requirements.txt

.PHONY: install
install:
	make deps
	rm -rf dist/*
	python setup.py sdist
	pip install dist/*

.PHONY: upload-pypi
upload-pypi:
	pip install --upgrade pip setuptools wheel
	pip install twine
	sh pypi_upload.sh