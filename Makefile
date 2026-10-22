# check: what a push must pass. The pre-push hook, the agents box's nightly fleet check and the
# GitHub workflow all run this one target. Node 20+ and corepack (yarn 4) are the only inputs.
.PHONY: check
check:
	yarn install --immutable
	yarn type-check
	yarn npm audit --all --recursive --environment production
	yarn build:all
	test -f tools-generated.json
	test -s index.js
	yarn validate
