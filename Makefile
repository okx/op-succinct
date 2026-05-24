# ── ci-env: dev environment lifecycle ─────────────────────────────────
# Usage:
#   make start ARGS="fp-mock"          # mock proving, zero Docker
#   make start ARGS="fp-tz"            # TradeZone fault proof
#   make start ARGS="fp-tz --mock"     # TradeZone + mock proofs
#   make start ARGS="fp-tz -m"         # TradeZone + monitoring
#   make start ARGS="fp-full"          # full proving + monitoring
#   make start ARGS="fp-full --tz"     # full + tz binaries
#   make stop                          # stop all
#   make stop ARGS="--clean"           # stop + clean data
#   make status                        # show service status
#   make clean                         # stop + clean all

ARGS ?=

.PHONY: start build-only stop status clean env-help

start:
	bash scripts/ci-env/start.sh $(ARGS)

build-only:
	bash scripts/ci-env/start.sh $(ARGS) --build-only

stop:
	bash scripts/ci-env/stop.sh $(ARGS)

status:
	bash scripts/ci-env/status.sh

clean:
	bash scripts/ci-env/stop.sh --clean

env-help:
	@echo "Usage:"
	@echo "  make start ARGS=\"fp-mock\"          # mock proving, zero Docker"
	@echo "  make start ARGS=\"fp-tz\"            # TradeZone fault proof"
	@echo "  make start ARGS=\"fp-tz --mock\"     # TradeZone + mock proofs"
	@echo "  make start ARGS=\"fp-tz -m\"         # TradeZone + monitoring"
	@echo "  make start ARGS=\"fp-full\"          # full proving + monitoring"
	@echo "  make start ARGS=\"fp-full --tz\"     # full + tz binaries"
	@echo "  make stop                          # stop all"
	@echo "  make stop ARGS=\"--clean\"           # stop + clean data"
	@echo "  make status                        # show service status"
	@echo "  make clean                         # stop + clean all"
