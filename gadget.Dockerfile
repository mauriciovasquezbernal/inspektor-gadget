# Prepare and build gadget artifacts in a container
ARG OS_TAG=18.04
FROM ubuntu:${OS_TAG} as builder

COPY ./ /gadget

RUN set -ex; \
	export DEBIAN_FRONTEND=noninteractive; \
	apt-get update && \
	apt-get install -y gcc make golang-1.13 ca-certificates git && \
	ln -s /usr/lib/go-1.13/bin/go /bin/go

RUN cd /gadget/gadget-container && make gadget-container-deps

# Builder: traceloop

# traceloop built from:
# https://github.com/kinvolk/traceloop/commit/3a57301aba445720c630ba99b58892da72a31e35
# See:
# - https://github.com/kinvolk/traceloop/actions
# - https://hub.docker.com/r/kinvolk/traceloop/tags

FROM docker.io/kinvolk/traceloop:202006050210553a5730 as traceloop

# Main gadget image

# BCC built from:
# https://github.com/kinvolk/bcc/commit/5fed2a94da19501c3088161db0c412b5623050ca
# See:
# - https://github.com/kinvolk/bcc/actions
# - https://hub.docker.com/r/kinvolk/bcc/tags

FROM docker.io/kinvolk/bcc:202006031708335fed2a

RUN set -ex; \
	export DEBIAN_FRONTEND=noninteractive; \
	apt-get update && \
	apt-get install -y --no-install-recommends \
		ca-certificates curl && \
        rmdir /usr/src && ln -sf /host/usr/src /usr/src

COPY gadget-container/entrypoint.sh gadget-container/cleanup.sh /

COPY --from=builder /gadget/gadget-container/bin/gadgettracermanager /bin/
COPY --from=builder /gadget/gadget-container/bin/networkpolicyadvisor /bin/

COPY gadget-container/gadgets/bcck8s /opt/

COPY --from=traceloop /bin/traceloop /bin/

## Hooks Begins

# OCI
COPY gadget-container/hooks/oci/prestart.sh gadget-container/hooks/oci/poststop.sh /opt/hooks/oci/
COPY --from=builder /gadget/gadget-container/bin/ocihookgadget /opt/hooks/oci/

# runc
COPY --from=builder /gadget/gadget-container/bin/runchooks.so /opt/hooks/runc/
COPY gadget-container/hooks/runc/add-hooks.jq /opt/hooks/runc/

# cri-o
COPY gadget-container/hooks/crio/gadget-prestart.json gadget-container/hooks/crio/gadget-poststop.json /opt/hooks/crio/

## Hooks Ends
