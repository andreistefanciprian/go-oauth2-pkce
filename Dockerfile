FROM golang:1.26-alpine AS builder
WORKDIR /app
COPY . .
ARG CMD
RUN go build -o /bin/app ./cmd/${CMD}

FROM alpine:latest
COPY --from=builder /bin/app /bin/app
ENTRYPOINT ["/bin/app"]
