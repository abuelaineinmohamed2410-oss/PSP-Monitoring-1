FROM node:20-slim
WORKDIR /app
COPY package.json ./
RUN apt-get update && apt-get install -y python3 make g++ --no-install-recommends && npm install --omit=dev && apt-get purge -y python3 make g++ && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*
COPY server.js index.html ./
ENV DB_FILE=/data/psp.db NODE_ENV=production
VOLUME /data
EXPOSE 3000
CMD ["node","server.js"]
