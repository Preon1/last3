# Last app container

FROM node:20-alpine AS client-build
WORKDIR /app/client
COPY client/package.json client/package-lock.json ./
RUN npm ci
COPY client ./
ARG VITE_WEBTRANSPORT_URL=
ARG VITE_REQUIRE_WEBTRANSPORT=1
ENV VITE_WEBTRANSPORT_URL=${VITE_WEBTRANSPORT_URL}
ENV VITE_REQUIRE_WEBTRANSPORT=${VITE_REQUIRE_WEBTRANSPORT}
RUN npm run build

FROM node:20-trixie-slim

RUN apt-get update \
	&& apt-get install -y --no-install-recommends openssl libstdc++6 ca-certificates git \
	&& rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY server/package.json server/package-lock.json ./server/
RUN cd server && npm ci --omit=dev

COPY server ./server
COPY --from=client-build /app/client/dist ./client/dist

RUN chmod +x /app/server/entrypoint.sh

ENV HOST=0.0.0.0
ENV PORT=8443
ENV WEBTRANSPORT_HOST=0.0.0.0
ENV WEBTRANSPORT_PORT=8444
ENV WEBTRANSPORT_PATH=/wt
ENV PUBLIC_DIR=/app/client/dist

# AUTO_TLS=1 will generate a self-signed cert (for personal/private use)
ENV AUTO_TLS=1

EXPOSE 8443

CMD ["/app/server/entrypoint.sh"]
