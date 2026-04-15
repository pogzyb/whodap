FILES := whodap/

MIN_PYTHON_VERSION := python3.10
export MIN_PYTHON_VERSION

VENV := ./venv/
export VENV

COMMON_VENV := rm -rf $(VENV); \
	$(MIN_PYTHON_VERSION) -m venv $(VENV); \
	source ./$(VENV)/bin/activate;

PIP_INSTALL := pip3 \
	--require-virtualenv \
	--disable-pip-version-check \
	--no-color \
	--no-cache-dir \
	install

prep: clean format check mypy tox

clean:
	rm -rf $(VENV) whodap.egg-info .mypy_cache .ruff_cache .tox
	rm -f *.1 *.2

format:
	ruff format $(FILES)

check:
	ruff check --fix $(FILES)

mypy:
	$(COMMON_VENV) \
	$(PIP_INSTALL) -r requirements.txt mypy; \
		mypy --strict --no-incremental $(FILES)
tox:
	tox -vv 2>$@.2 | tee $@.1
