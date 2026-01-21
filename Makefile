.PHONY: certs server client test

certs:
	python -m qasccs.tools.gen_certs --out qasccs/secure_channel/certs

server:
	python -m qasccs.secure_channel.server --host 127.0.0.1 --port 8443

client:
	python -m qasccs.secure_channel.client --host 127.0.0.1 --port 8443 --data-lifetime-years 10 --data-classification high

test:
	pytest -q
