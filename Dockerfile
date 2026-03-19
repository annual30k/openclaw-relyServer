FROM node:22-alpine

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install

COPY tsconfig.json ./
COPY src ./src
COPY mysql ./mysql

RUN npm run build

EXPOSE 8080

CMD ["npm", "run", "start"]
