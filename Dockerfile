# =========================================================================
# SILHOUETTE REAPER - PRODUCTION DOCKERFILE
# Multi-stage optimized Node.js build with persistent storage mounting
# =========================================================================

# Stage 1: Dependencies
FROM node:22-alpine AS deps
RUN apk add --no-cache libc6-compat
WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

# Stage 2: Builder
FROM node:22-alpine AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .

ENV NEXT_TELEMETRY_DISABLED=1
ENV NODE_ENV=production

RUN npm run build

# Stage 3: Runner
FROM node:22-alpine AS runner
WORKDIR /app

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV PORT=3000
ENV HOSTNAME="0.0.0.0"

# Create non-root user for security
RUN addgroup --system --gid 1001 nodejs && \
    adduser --system --uid 1001 nextjs

# Create persistent storage directories with proper permissions
RUN mkdir -p /app/storage/database \
             /app/storage/evidence_vault \
             /app/storage/artifacts_store \
             /app/storage/reports_registry && \
    chown -R nextjs:nodejs /app/storage

# Copy built application and node_modules
COPY --from=builder /app/public ./public
COPY --from=builder /app/.next ./.next
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./package.json
COPY --from=builder /app/next.config.js ./next.config.js

USER nextjs

EXPOSE 3000

# Volume mount point for persistent database and evidence vaults
VOLUME ["/app/storage"]

CMD ["npm", "run", "start"]
