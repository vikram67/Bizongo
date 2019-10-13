# Set the base image to Ubuntu
FROM    ubuntu

# File Author / Maintainer
MAINTAINER nodejs_assessment

# Install Node.js and other dependencies
RUN apt-get update && \
    apt-get -y install  npm curl && \
    curl -sL https://deb.nodesource.com/setup_6.x | bash - && \
    apt-get -y install python build-essential nodejs

# Provides cached layer for node_modules
ADD package.json /tmp/package.json
RUN cd /tmp && npm install
RUN mkdir -p /src && cp -a /tmp/node_modules /src/

# Define working directory
WORKDIR /src
ADD . /src

# Expose port
EXPOSE  8500

# Run app using nodemon
CMD ["node", "/src/index.js"]
