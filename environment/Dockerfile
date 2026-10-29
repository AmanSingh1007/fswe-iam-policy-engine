# Agent and verifier share this image. Pinned base; the engine may be written in
# Python (provided) or anything that runs from /app/iamctl.
FROM public.ecr.aws/docker/library/python:3.13-slim-bookworm@sha256:01f42367a0a94ad4bc17111776fd66e3500c1d87c15bbd6055b7371d39c124fb

ENV DEBIAN_FRONTEND=noninteractive LANG=C.UTF-8
RUN apt-get update \
 && apt-get install -y --no-install-recommends procps \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -m -s /bin/bash agent

WORKDIR /app
COPY workspace/ /app/
RUN chmod 755 /app/iamctl && mkdir -p /logs/verifier && chown -R agent:agent /app
