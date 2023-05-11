HELM ?= helm
HELM_DOCS_IMAGE ?= jnorwood/helm-docs:v1.11.0
BUILD_DIR ?= bin
OUTPUT_DIR ?= $(BUILD_DIR)
CHART_DIR := $(BUILD_DIR)/gadget

IMAGE_TAG := $(shell git describe --tags --abbrev=0 --match "v*")
# CHART_VERSION must be a valid SemVer string so strip the leading 'v'
CHART_VERSION := $(IMAGE_TAG:v%=%)
APP_VERSION ?= $(IMAGE_TAG)

clean:
	rm -rf $(BUILD_DIR)

build: clean
	@echo "Building chart:"
	mkdir -p $(BUILD_DIR)
	cp -r gadget $(BUILD_DIR)
	cp -r ../pkg/resources/crd/bases $(CHART_DIR)/crds
	mv $(CHART_DIR)/Chart.yaml.tmpl $(CHART_DIR)/Chart.yaml
	sed -i "s/%VERSION%/$(CHART_VERSION)/g" $(CHART_DIR)/Chart.yaml
	sed -i "s/%APP_VERSION%/$(APP_VERSION)/g" $(CHART_DIR)/Chart.yaml
	@echo "Preparing docs"
	docker run --user $(shell id -u):$(shell id -g) -v $(shell pwd)/$(CHART_DIR):/helm-docs $(HELM_DOCS_IMAGE) -s file
	@echo "Charts available at: $(CHART_DIR)"

# install uses 'helm upgrade --install' to make chart installation idempotent,
# also helm upgrade does not update CRDs so we need to apply them separately
install: build
	$(HELM) upgrade --install gadget $(CHART_DIR) --namespace gadget --create-namespace
	kubectl apply -f $(CHART_DIR)/crds

uninstall:
	$(HELM) uninstall gadget --namespace gadget
	kubectl delete -f $(CHART_DIR)/crds

lint: build
	$(HELM) lint $(CHART_DIR)

template: build
	$(HELM) template gadget $(CHART_DIR) --namespace gadget --skip-crds | tee $(OUTPUT_DIR)/deploy.yaml

package: build
	$(HELM) package $(CHART_DIR) -d $(BUILD_DIR)
