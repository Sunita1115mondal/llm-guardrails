PY  ?= ~/miniconda3/envs/personal/bin/python
PIP ?= ~/miniconda3/envs/personal/bin/pip

.PHONY: install eval serve test

install:
	$(PIP) install -e ".[all]"

eval:
	$(PY) -m guardrails.evaluate

serve:
	$(PY) -m uvicorn api.main:app --reload --port 8000

test:
	$(PY) -m pytest -q
