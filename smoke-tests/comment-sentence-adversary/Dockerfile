FROM node:22-alpine

WORKDIR /adversary
COPY package.json ./
COPY dist ./dist
COPY vendor ./vendor
RUN mkdir -p node_modules/@adversary \
  && cp -R vendor/adversary-sdk node_modules/@adversary/sdk \
  && printf '#!/bin/sh\nexec node /adversary/dist/run.js\n' > /adversary/run \
  && chmod +x /adversary/run

CMD ["/adversary/run"]
