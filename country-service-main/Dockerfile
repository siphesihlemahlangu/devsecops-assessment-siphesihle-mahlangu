#chat keep this: # Multi-stage build for minimal, secure container
# Stage 1: Build environment
FROM node:18-alpine3.17 AS builder

# Install security updates and build dependencies
RUN apk update && apk upgrade --no-cache && \
    apk add --no-cache --virtual .build-deps \
    git \
    python3 \
    make \
    g++

# Create non-root user for build stage
RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

# Set working directory and ownership
WORKDIR /app
COPY package*.json ./
RUN chown -R appuser:appgroup /app

# Switch to non-root user
USER appuser

# Install dependencies
RUN npm ci --only=production --ignore-scripts

# Stage 2: Production environment
FROM node:18-alpine3.17 AS runtime

# Security hardening
RUN apk update && apk upgrade --no-cache && \
    apk add --no-cache tini && \
    rm -rf /var/cache/apk/*

# Create non-root user and group
RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

# Set environment variables for security
ENV NODE_ENV=production
ENV NPM_CONFIG_LOGLEVEL=warn
ENV NPM_CONFIG_AUDIT=false
ENV NPM_CONFIG_FUND=false
ENV NPM_CONFIG_UPDATE_NOTIFIER=false

# Create app directory with proper permissions
WORKDIR /app
RUN chown -R appuser:appgroup /app

# Copy application files from builder
COPY --from=builder --chown=appuser:appgroup /app/node_modules ./node_modules
COPY --chown=appuser:appgroup . .

# Remove setuid/setgid binaries for additional security
RUN find / -xdev -perm -6000 -type f -exec chmod a-s {} \; || true

# Switch to non-root user
USER appuser

# Use tini as init process for proper signal handling
ENTRYPOINT ["/sbin/tini", "--"]

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD node healthcheck.js || exit 1

# Expose application port
EXPOSE 3000

# Start application
CMD ["node", "server.js"]