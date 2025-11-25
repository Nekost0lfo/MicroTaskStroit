FROM node:18-alpine

WORKDIR /app

ENV NODE_ENV=production
ENV PORT=8100

COPY package*.json ./
RUN npm install --production

COPY . .

EXPOSE 8100

CMD ["npm", "start"]