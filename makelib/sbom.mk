# ====================================================================================
# Setup SBOM

SYFT_VERSION ?= 1.41.1
SYFT := $(TOOLS_HOST_DIR)/syft-$(SYFT_VERSION)

$(SYFT):
	@$(INFO) installing syft $(SYFT_VERSION)
	@mkdir -p $(TOOLS_HOST_DIR)
	@curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b $(TOOLS_HOST_DIR) v$(SYFT_VERSION)
	@mv $(TOOLS_HOST_DIR)/syft $(SYFT)
	@$(OK) installing syft $(SYFT_VERSION)

sbom.generate: $(SYFT)
	@$(INFO) generating SBOM
	@$(SYFT) . --source-name $(PROJECT_NAME) --source-version $(VERSION) -o spdx-json=extensions/sbom/sbom.spdx.json
	@$(OK) generating SBOM

.PHONY: sbom.generate
