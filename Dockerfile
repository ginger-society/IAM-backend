FROM gingersociety/rust-rocket-api-builder:latest as builder

# Create a new directory for the app
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . .

# Build the application in release mode
RUN cargo build --release

# Second stage: Create the minimal runtime image
FROM gingersociety/rust-rocket-api-runner:latest

# Copy the compiled binary from the builder stage
COPY --from=builder /app/target/release/IAMService /app/

# Set the working directory
WORKDIR /app


# Run the executable when the container starts
ENTRYPOINT ["./IAMService"]
