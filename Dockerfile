FROM python:3.12.14-slim-bookworm@sha256:782412e85d0f0984994c290652577d4018aff08145c85b262bb63dc0c7522254 AS library_build
RUN apt-get update && apt-get install --yes --no-install-recommends build-essential gperf ca-certificates \
    && rm -rf /var/lib/apt/lists/*
# Official 2.6.1 release and signed-release SHA256; no older filter compiler fallback.
ADD --checksum=sha256:501f66c667225d53791b97e1d7cf85ab764c297d04881f60f38f451c4b0ee1be \
    https://github.com/seccomp/libseccomp/releases/download/v2.6.1/libseccomp-2.6.1.tar.gz /tmp/libseccomp.tar.gz
RUN tar -xzf /tmp/libseccomp.tar.gz -C /tmp \
    && cd /tmp/libseccomp-2.6.1 && ./configure --disable-static --disable-python \
    && make -j2 && make install

FROM python:3.12.14-slim-bookworm@sha256:782412e85d0f0984994c290652577d4018aff08145c85b262bb63dc0c7522254
COPY --from=library_build /usr/local/lib/libseccomp.so* /usr/local/lib/
RUN ldconfig && python -m pip install --no-cache-dir uv==0.12.5
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/reference UV_CACHE_DIR=/tmp/uv PATH=/opt/reference/bin:${PATH}
WORKDIR /reference
COPY pyproject.toml uv.lock README.md LICENSE ./
RUN uv sync --frozen --extra verification --no-install-project
COPY . .
RUN uv sync --frozen --extra verification --no-editable
USER 10000:10000
CMD ["python", "scripts/verify_linux.py"]
