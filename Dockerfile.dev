FROM rust:1-slim-bullseye

RUN apt update
RUN apt install curl zsh nano docker.io pkg-config libssl-dev gcc-mingw-w64-x86-64 libpq-dev -y
RUN sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" -y

RUN rustup target add x86_64-pc-windows-gnu
RUN rustup component add rustfmt
RUN echo "zsh" >> ~/.bashrc