# --- Étape 1 : récupérer les binaires de recon (ProjectDiscovery, Linux amd64) ---
FROM python:3.12-slim AS tools
ARG SUBFINDER_VERSION=2.6.6
ARG HTTPX_VERSION=1.6.9
ARG KATANA_VERSION=1.1.0
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl unzip ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /dl
RUN set -eux; \
    base=https://github.com/projectdiscovery; \
    curl -sSLo sf.zip $base/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_amd64.zip; \
    curl -sSLo hx.zip $base/httpx/releases/download/v${HTTPX_VERSION}/httpx_${HTTPX_VERSION}_linux_amd64.zip; \
    curl -sSLo kt.zip $base/katana/releases/download/v${KATANA_VERSION}/katana_${KATANA_VERSION}_linux_amd64.zip; \
    unzip -o sf.zip subfinder; unzip -o hx.zip httpx; unzip -o kt.zip katana; \
    chmod +x subfinder httpx katana

# --- Étape 2 : image du worker ---
FROM python:3.12-slim
WORKDIR /app
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=tools /dl/subfinder /dl/httpx /dl/katana /usr/local/bin/

COPY engine/requirements.txt ./engine/requirements.txt
RUN pip install --no-cache-dir -r engine/requirements.txt
# Valide tldextract avec le snapshot de suffixes BUNDLÉ (suffix_list_urls=()) : aucune
# requête réseau au démarrage, comportement identique hors-ligne.
RUN python -c "import tldextract; e=tldextract.TLDExtract(suffix_list_urls=())('a.example.co.uk'); assert e.registered_domain=='example.co.uk', e; print('tldextract OK (offline snapshot)')"

COPY engine/ ./engine/
COPY knowledge/ ./knowledge/

# Concurrence bornée et éditable (défaut conservateur). Plusieurs hosts DISTINCTS en
# parallèle ; l'admission centrale (ratelimit) garantit un seul worker par host.
CMD ["sh", "-c", "celery -A engine.celery_app worker --loglevel=INFO --concurrency=${CELERY_CONCURRENCY:-8}"]
