FROM rust:1.29.2

WORKDIR /usr/src/crust
COPY . .
RUN apt-get update -y && \
    mkdir /target && \
    apt-get clean -y && \
    rm -rf /var/lib/apt/lists/* && \
    cargo build --tests --release --verbose --target-dir /target

CMD cargo test --release --verbose --target-dir /target
