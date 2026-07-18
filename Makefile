.PHONY: install install-local model test run run-local clean

WHEELS = https://abetlen.github.io/llama-cpp-python/whl/cpu

.venv:
	python3 -m venv .venv
	.venv/bin/pip install -r requirements.txt

install: .venv

# Stamp file so `make run-local` re-checks deps cheaply instead of reinstalling.
.venv/.local-deps: .venv requirements-local.txt
	.venv/bin/pip install --extra-index-url $(WHEELS) -r requirements-local.txt
	touch $@

install-local: .venv/.local-deps

model: .venv
	.venv/bin/python -m insecure_ai_app.download_model

test: .venv
	.venv/bin/pytest

run: .venv
	.venv/bin/uvicorn insecure_ai_app.asgi:app --reload --port 8000

# One command: installs the extra dep, fetches the model, starts the server.
# No --reload here -- it would reload 1.1 GB of weights on every edit.
run-local: .venv/.local-deps model
	LLM_PROVIDER=local .venv/bin/uvicorn insecure_ai_app.asgi:app --port 8000

clean:
	rm -f runtime/app.db runtime/credentials.txt runtime/mcp_tools.json
	rm -f runtime/audit.log runtime/guarded_audit.log runtime/evil_manifest.json
	rm -f runtime/outbox/*.eml runtime/documents/*.txt
