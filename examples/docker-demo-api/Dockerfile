FROM node:24-alpine

WORKDIR /app

COPY package.json ./

RUN npm install --omit=dev

COPY server.js ./

ENV PORT=3000

EXPOSE 3000

CMD ["npm", "start"]
