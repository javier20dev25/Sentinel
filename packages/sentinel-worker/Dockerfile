FROM node:22-slim

# Install git
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy everything from current directory (which is packages/sentinel-worker)
COPY . .

# Install dependencies
RUN npm install

# Start the worker
CMD ["node", "index.js"]
