.PHONY: install build typecheck lint test dev start compose-up compose-down

install:
	pnpm install

typecheck:
	pnpm typecheck

lint:
	pnpm lint

test:
	pnpm test

build:
	pnpm build

dev:
	pnpm dev

start:
	pnpm start

compose-up:
	docker compose -f deploy/compose.yaml up -d

compose-down:
	docker compose -f deploy/compose.yaml down
