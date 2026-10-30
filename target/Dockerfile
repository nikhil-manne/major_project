# INTENTIONALLY INSECURE TEST TARGET — use only in an isolated local lab.
# Old/EOL base image and root execution are intentional scanner test cases.
FROM node:18-bullseye-slim
WORKDIR /app
COPY app.js ./app.js
USER root
ENV NODE_ENV=production
EXPOSE 3000
CMD ["node", "app.js"]
