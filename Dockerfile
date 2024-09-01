FROM gingersociety/rust-rocket-api-builder:latest as builder

ARG GINGER_TOKEN

# Create a new directory for the app
WORKDIR /app
COPY . .
# Run the ginger-auth command and capture the output
RUN output=$(ginger-auth token-login $GINGER_TOKEN) && \
    eval "$output" && \
    echo "GINGER_API_TOKEN=$GINGER_API_TOKEN" >> /app/.env

# Set the environment variable in Dockerfile using the ENV directive
ARG GINGER_API_TOKEN
ENV GINGER_API_TOKEN=${GINGER_API_TOKEN}
# Optionally, you can also print it from the .env file
# RUN cat /app/.env
# # Copy the current directory contents into the container at /app

RUN ginger-connector update-pipeline stage running

# Build the application in release mode
RUN cargo build --release

# Second stage: Create the minimal runtime image
FROM gingersociety/rust-rocket-api-runner:latest

# Copy the compiled binary from the builder stage
COPY --from=builder /app/target/release/IAMService /app/
COPY --from=builder /app/.env /app/

# Set the working directory
WORKDIR /app

# Set environment variables for the runtime
ENV GINGER_API_TOKEN=${GINGER_API_TOKEN}

RUN ginger-connector update-pipeline stage passing

# Run the executable when the container starts
ENTRYPOINT ["./IAMService"]
