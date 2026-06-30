# Stage 1 — build the React frontend (build-only; no node artifacts reach the runtime image)
# hadolint ignore=DL3007
FROM node:lts-alpine AS ui-builder

WORKDIR /app/web

COPY web/package.json web/package-lock.json ./
RUN npm ci

COPY web/ ./
RUN npm run build

# Stage 2 — build the Go binary with embedded assets
FROM golang:1.26-alpine AS go-builder
ARG TARGETOS
ARG TARGETARCH
WORKDIR /app

RUN apk add --no-cache git

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Replace the placeholder static/dist with the real frontend build
COPY --from=ui-builder /app/web/dist ./static/dist

RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -o main .

# Stage 3 — minimal runtime image
FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=go-builder /app/main .
EXPOSE 8080

USER 65532:65532

CMD ["./main"]
