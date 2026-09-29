.PHONY: install unit integration test certs docker-up docker-scan docker-down demo-ssh demo-tls

install:
	pip install -e ".[pdf]"
	pip install -r requirements-dev.txt

# --- No Docker needed -------------------------------------------------------
unit:
	pytest tests/unit -v

# Self-contained: starts an in-process fake SSH server and (if the openssl CLI exists) a legacy TLS server
integration:
	pytest tests/integration -v

test:
	pytest -v

# Manual targets for trying the CLI by hand (run each in its own terminal)
demo-ssh:
	python -m tests.fixtures.fake_ssh 2222 weak

demo-tls: certs
	openssl s_server -accept 4433 -cert docker/certs/self-signed.pem -key docker/certs/self-signed.key \
	  -tls1_1 -cipher 'AES128-SHA:NULL-SHA:ADH-AES128-SHA:@SECLEVEL=0' -quiet

# --- Docker fixtures (optional) ----------------------------------------------
certs:
	sh docker/certs/generate.sh

docker-up: certs
	docker compose up --build -d legacy-tls-target legacy-ssh-target

docker-scan:
	cryptoscan localhost -p 4433 --protocol tls
	cryptoscan localhost -p 2222 --protocol ssh

docker-down:
	docker compose down -v
