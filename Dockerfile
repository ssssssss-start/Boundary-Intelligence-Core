FROM python:3.12-slim-bookworm

ARG DEBIAN_MIRROR=https://mirrors.aliyun.com

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    sed -i \
        -e "s|http://deb.debian.org/debian|${DEBIAN_MIRROR}/debian|g" \
        -e "s|http://deb.debian.org/debian-security|${DEBIAN_MIRROR}/debian-security|g" \
        /etc/apt/sources.list.d/debian.sources \
    && apt-get -o Acquire::Retries=5 update \
    && apt-get -o Acquire::Retries=5 install --yes --no-install-recommends \
        build-essential \
        libsndfile1 \
        zlib1g-dev

COPY requirements.txt /app/requirements.txt
RUN python -m pip install --upgrade pip \
    && python -m pip install -r /app/requirements.txt

COPY app /app/app
COPY data /app/data
COPY tts /app/tts

RUN mkdir -p /app/output \
    && useradd --create-home --uid 10001 anti-fraud \
    && chown -R anti-fraud:anti-fraud /app

USER anti-fraud

EXPOSE 8000 8001

CMD ["python", "-m", "uvicorn", "app.query_process.api.app:app", "--host", "0.0.0.0", "--port", "8001"]
