
.PHONY: run
run:
	docker compose build && docker compose up

.PHONY: docker-clean-data
clean:
	docker compose down -v && \
	docker container prune -f && \
	docker network prune -f && \
	rm -rf certvault/certs && \
	rm -rf certvault/file && \
	rm -rf certvault/logs && \
	rm -rf certvault/data
