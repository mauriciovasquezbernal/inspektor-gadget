SHELL := /bin/bash

IMAGE_TAG ?= $(shell ../tools/image-tag branch)
CONTAINER_REGISTRY ?= ghcr.io/inspektor-gadget

GADGETS = \
	trace_dns \
	trace_exec \
	trace_open \
	trace_tcpconnect \
	trace_tcpretrans \
	#

.PHONY: all
all: $(GADGETS)

#TODO: How to create an independent target for each gadget do this can be run in parallel?
.PHONY:
build:
	@echo "Building all gadgets"
	@for GADGET in $(GADGETS); do \
		CATEGORY=$$(echo $$GADGET | cut -d_ -f1) && \
		NAME=$$(echo $$GADGET | cut -d_ -f2) && \
		pushd $$CATEGORY/$$NAME/ && \
		IG_EXPERIMENTAL=true ig image build $(CONTAINER_REGISTRY)/$$GADGET:$(IMAGE_TAG) &&  \
		popd; \
	done

.PHONY:
push: build
	@echo "Pushing all gadgets"
	for GADGET in $(GADGETS); do \
		IG_EXPERIMENTAL=true ig image push $(CONTAINER_REGISTRY)/$$GADGET:$(IMAGE_TAG); \
	done
