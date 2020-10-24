FROM alpine:3.12
RUN apk --no-cache add ca-certificates git rpm
ENV TRIVY_CACHE_DIR /trivy
ENV FANAL_APK_INDEX_ARCHIVE_URL 'file:///trivy/apkindex-archive/alpine/v%s/main/x86_64/history.json'
WORKDIR /trivy/db
RUN wget https://github.com/aquasecurity/trivy-db/releases/latest/download/trivy-offline.db.tgz && \
    tar xvf trivy-offline.db.tgz && rm trivy-offline.db.tgz && \
    cd /trivy && \
    git clone --depth 1 https://github.com/knqyf263/apkindex-archive.git && \
    rm -rf apkindex-archive/.git

COPY trivy /usr/local/bin/trivy
