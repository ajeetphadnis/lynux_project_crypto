FROM node:20.7
WORKDIR com.utes.cert.crypto
COPY /com.utes.cert.crypto/package*.json .
COPY . .
RUN npm install
EXPOSE 30005:30005
EXPOSE 30085:30085
# RUN cd /com.utes.cert.crypto
# CMD [ "node" , "pha_cryptoKeyEncDecSrv.js" ]
