FROM node:22-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY tsconfig.json ./

# Install dependencies
RUN npm ci --only=production
RUN npm install -g tsx

# Copy source
COPY src/ ./src/

# Create geoip directory (database downloaded separately)
RUN mkdir -p geoip

# Expose port
EXPOSE 5000

# Start command
CMD ["tsx", "src/index.ts"]
