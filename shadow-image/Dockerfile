FROM rust:1-alpine AS build
RUN apk add --no-cache build-base
WORKDIR /sensor
COPY sensor/Cargo.toml sensor/Cargo.lock ./
COPY sensor/src ./src
RUN cargo build --release

FROM alpine:3.19
RUN apk add --no-cache strace bash
COPY --from=build /sensor/target/release/sensor /sensor/sensor
WORKDIR /samples
CMD ["sleep", "infinity"]
