# First stage: Build the Rust application
FROM rust:1-slim-bullseye as builder
RUN apt-get update && apt-get install -y pkg-config libssl-dev libpq-dev

# Create a new directory for the app
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . .

# Build the application in release mode
RUN cargo build --release

# Second stage: Create the minimal runtime image
FROM debian:bullseye-slim

# Install necessary dependencies
RUN apt-get update && apt-get install -y \
    libssl1.1 \
    libpq5 \
    libgcc1 \
    libc6 \
    && rm -rf /var/lib/apt/lists/*

# Copy the compiled binary from the builder stage
COPY --from=builder /app/target/release/IAMService /app/

# Set the working directory
WORKDIR /app


# Run the executable when the container starts
ENTRYPOINT ["./IAMService"]
