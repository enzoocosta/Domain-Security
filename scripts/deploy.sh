#!/bin/bash
set -euo pipefail

echo "===> [1/4] Atualizando codigo..."
git pull origin main

echo "===> [2/4] Buildando imagem..."
docker compose build --no-cache app

echo "===> [3/4] Reiniciando aplicacao (sem derrubar Caddy)..."
docker compose up -d --no-deps app

echo "===> [4/4] Limpando imagens antigas..."
docker image prune -f

echo ""
echo "Deploy concluido."
echo "  App:    http://localhost:8000/health"
echo "  Caddy:  docker compose logs caddy"
