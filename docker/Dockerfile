FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends proxychains4 nmap ca-certificates \
    && rm -rf /var/lib/apt/lists/* && useradd -m -u 1000 recon
WORKDIR /app
COPY pyproject.toml LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir .
USER recon
ENV RECONFORGE_CONFIG_DIR=/home/recon/config RECONFORGE_DATA_DIR=/home/recon/data
EXPOSE 8787
ENTRYPOINT ["reconforge"]
CMD ["serve", "--host", "0.0.0.0"]
