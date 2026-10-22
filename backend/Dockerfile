FROM node:22-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY tsconfig.json ./

# Install dependencies
RUN npm ci --only=production
# tsx is a dev dependency; pinned to package-lock.json's version so every build runs the same one.
RUN npm install -g tsx@4.23.11

# Copy source
COPY src/ ./src/

# Create geoip directory (database downloaded separately)
RUN mkdir -p geoip

# Expose port
EXPOSE 5000

# Start command
CMD ["tsx", "src/index.ts"]
