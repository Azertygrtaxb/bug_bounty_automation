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

# pip D'ABORD : le SDK anthropic tire python-httpx, qui pose un script console `httpx` dans
# /usr/local/bin. On installe donc les binaires ProjectDiscovery APRÈS, dans un répertoire
# DÉDIÉ préfixé au PATH -> plus aucune dépendance Python ne peut les masquer (A1.1).
COPY engine/requirements.txt ./engine/requirements.txt
RUN pip install --no-cache-dir -r engine/requirements.txt
RUN python -c "import tldextract; e=tldextract.TLDExtract(suffix_list_urls=())('a.example.co.uk'); assert e.registered_domain=='example.co.uk', e; print('tldextract OK (offline snapshot)')"

COPY --from=tools /dl/subfinder /dl/httpx /dl/katana /opt/pd/bin/
ENV PATH="/opt/pd/bin:${PATH}"

COPY engine/ ./engine/
COPY knowledge/ ./knowledge/

# GARDE-FOU BUILD : `httpx` du PATH DOIT être le binaire ProjectDiscovery (pas le script pip).
# Échoue le build sinon — six heures de crawl à vide deviennent une erreur immédiate (A1.2).
RUN python -m engine.recon.binaires

# Concurrence bornée et éditable. Le garde-fou binaires tourne aussi au DÉMARRAGE : le
# worker refuse de démarrer si un binaire externe a été masqué.
# --beat embarque le planificateur DANS le worker (Celery Beat) : le juge sémantique
# continu (celery_app.beat_schedule, actif si SEM_BEAT_ACTIF=1) est déclenché sans service
# séparé. --schedulefile sous /tmp = état de Beat (dernier tick) qui survit à un restart.
CMD ["sh", "-c", "python -m engine.recon.binaires && celery -A engine.celery_app worker --beat --schedule=/tmp/celerybeat-schedule --loglevel=INFO --concurrency=${CELERY_CONCURRENCY:-2} --prefetch-multiplier=${CELERY_PREFETCH_MULTIPLIER:-1} --max-tasks-per-child=${CELERY_MAX_TASKS_PER_CHILD:-1}"]
