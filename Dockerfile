# -------------------------------------------------------------
# Stage 1: Build React + TypeScript + Tailwind frontend
# -------------------------------------------------------------
FROM node:20-alpine AS frontend-builder
WORKDIR /build

COPY frontend/package*.json ./
RUN npm install

COPY frontend/ ./
RUN npm run build

# -------------------------------------------------------------
# Stage 2: Production Python FastAPI Backend & Static UI
# -------------------------------------------------------------
FROM python:3.12-slim AS runner

WORKDIR /app

# Install system utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python requirements
COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install --no-cache-dir -r ./backend/requirements.txt

# Copy Backend Application
COPY backend/ ./backend/

# Copy Pre-built Frontend distribution
COPY --from=frontend-builder /build/dist ./frontend/dist

WORKDIR /app/backend

EXPOSE 8000

ENV PYTHONUNBUFFERED=1
ENV DATABASE_URL="sqlite:///./nids.db"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
