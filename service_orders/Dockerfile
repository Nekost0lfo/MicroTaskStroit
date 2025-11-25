FROM node:18-alpine

WORKDIR /app

ENV NODE_ENV=production
ENV PORT=8200

COPY package*.json ./
RUN npm install --production

COPY . .

EXPOSE 8200

CMD ["npm", "start"]