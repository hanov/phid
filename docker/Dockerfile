FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md LICENSE NOTICE COMMERCIAL.md LICENSE-COMMERCIAL.md CONTRIBUTING.md ./
COPY phi_security ./phi_security
RUN pip install --no-cache-dir . && useradd --create-home phi && mkdir /data && chown phi:phi /data
COPY config ./config
ENV PHI_DB=/data/phi-security.db
USER phi
VOLUME ["/data"]
ENTRYPOINT ["phi-sec"]
CMD ["--help"]
