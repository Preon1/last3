# Last app container

FROM node:20-alpine AS client-build
WORKDIR /app/client
COPY client/package.json client/package-lock.json ./
RUN npm ci
COPY client ./
RUN npm run build

FROM node:20-alpine

RUN apk add --no-cache openssl

WORKDIR /app

COPY server/package.json ./server/package.json
RUN cd server && npm install --omit=dev

COPY server ./server
COPY --from=client-build /app/client/dist ./client/dist

RUN chmod +x /app/server/entrypoint.sh

ENV HOST=0.0.0.0
ENV PORT=8443
ENV PUBLIC_DIR=/app/client/dist

# AUTO_TLS=1 will generate a self-signed cert (for personal/private use)
ENV AUTO_TLS=1

EXPOSE 8443

CMD ["/app/server/entrypoint.sh"]
