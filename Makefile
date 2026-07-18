.PHONY: install test run clean

install:
	python3 -m venv .venv
	.venv/bin/pip install -r requirements.txt

test:
	.venv/bin/pytest

run:
	.venv/bin/uvicorn insecure_ai_app.asgi:app --reload --port 8000

clean:
	rm -f runtime/app.db runtime/credentials.txt runtime/mcp_tools.json
	rm -f runtime/audit.log runtime/guarded_audit.log runtime/evil_manifest.json
	rm -f runtime/outbox/*.eml runtime/documents/*.txt
