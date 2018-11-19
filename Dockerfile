FROM rust:1.29.2

RUN apt-get update -y && mkdir /target

WORKDIR /usr/src/crust
COPY . .
RUN cargo build --release --verbose --target-dir /target

CMD cargo test --release --verbose --target-dir /target
