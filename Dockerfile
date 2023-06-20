FROM rust:1.67 as builder
WORKDIR /usr/src/jwt_issuer
COPY . .
RUN cargo install --path . 

FROM debian:bullseye-slim
RUN apt-get update 
# RUN apt-get install -y extra-runtime-dependencies 
RUN rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/local/cargo/bin/jwt_issuer /usr/local/bin/jwt_issuer
COPY --from=builder /usr/src/jwt_issuer/private_key.pem /usr/local/bin/private_key.pem

ENV PEM_FILE /usr/local/bin/private_key.pem
CMD ["jwt_issuer"]