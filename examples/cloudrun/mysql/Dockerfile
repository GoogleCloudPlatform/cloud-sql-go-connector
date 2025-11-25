# Use the official Golang image to create a build artifact.
# This is based on Debian and sets the GOPATH to /go.
# https://hub.docker.com/_/golang
FROM golang:1.25 AS builder

# Create and change to the app directory.
WORKDIR /app

# Retrieve application dependencies.
# This allows the container build to reuse cached dependencies.
# Expecting to copy go.mod and if present go.sum.
COPY go.* ./
RUN go mod download

# Copy local code to the container image.
COPY . .

# Build the binary.
# CGO_ENABLED=0 builds a statically-linked binary.
RUN CGO_ENABLED=0 GOOS=linux go build -v -o server

# Use gcr.io/distroless/static:nonroot image to run the application.
FROM gcr.io/distroless/static:nonroot

# Copy the binary to the production image from the builder stage.
COPY --from=builder /app/server /server

# Run the web service on container startup.
CMD ["/server"]
