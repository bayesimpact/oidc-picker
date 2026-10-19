FROM node:24-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY src ./src
ENV OIDC_PICKER_HOST=0.0.0.0
EXPOSE 5556
USER node
ENTRYPOINT ["node", "src/cli.ts"]
CMD ["/config/oidc-picker.yaml"]
