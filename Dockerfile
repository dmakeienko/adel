# Stage 1 — build the React frontend (build-only; no node artifacts reach the runtime image)
# hadolint ignore=DL3007
FROM node:lts-alpine AS ui-builder

WORKDIR /app/web

COPY web/package.json web/package-lock.json ./
RUN npm ci

COPY web/ ./
RUN npm run build

# Stage 2 — build the Go binary with embedded assets
FROM golang:1.25-alpine3.23 AS go-builder

WORKDIR /app

RUN apk add --no-cache git

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Replace the placeholder static/dist with the real frontend build
COPY --from=ui-builder /app/web/dist ./static/dist

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main .

# Stage 3 — minimal runtime image
FROM alpine:3.23

RUN apk --no-cache add ca-certificates

RUN addgroup -g 1001 -S adel && \
    adduser -S adel -u 1001

WORKDIR /home/adel

COPY --from=go-builder /app/main .

RUN chown adel:adel main

USER adel

EXPOSE 8080

CMD ["./main"]
