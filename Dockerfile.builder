FROM containers.gingersociety.org/rust-rocket-api-builder:latest as builder

# Create a new directory for the app
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . .

ARG GINGER_TOKEN
ENV GINGER_TOKEN=$GINGER_TOKEN

RUN ginger-auth token-login $GINGER_TOKEN
RUN ginger-connector connect prod-k8

# Execute the build script
RUN cargo build --release


