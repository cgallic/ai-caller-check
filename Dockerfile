FROM node:22-alpine
WORKDIR /app
COPY package.json server.js LICENSE ./
COPY src ./src
COPY bin ./bin
COPY widget ./widget
ENV PORT=8787
EXPOSE 8787
USER node
CMD ["node", "server.js"]
