# Use the official Python 3.11 image
FROM python:3.11


# Set environment variables to avoid prompts during installation
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH="/app:$PYTHONPATH"

RUN apt-get update && apt-get install -y \
    g++ \
    make \
    cmake \
    unzip \
    zip \
    libcurl4-openssl-dev \
    autoconf \
    libtool

RUN apt install -y software-properties-common
run apt-get install -y openjdk-17-jre-headless

# RUN apt-get update && apt-get install -y git protobuf-compiler automake gzip tar autoconf libtool libkrb5-dev allure

# Install required system packages
# RUN apt-get update && apt-get install -y \
#     curl \
#     git \
#     unzip \
#     apt-get update

RUN apt-get update && apt-get install -y libcanberra-gtk-module libcanberra-gtk3-module

# install allure
RUN curl -o allure-2.32.0.tgz -OLs https://repo.maven.apache.org/maven2/io/qameta/allure/allure-commandline/2.32.0/allure-commandline-2.32.0.tgz
RUN tar -zxvf allure-2.32.0.tgz -C /opt/
RUN ln -s /opt/allure-2.32.0/bin/allure /usr/bin/allure
ENV JAVA_HOME /usr/lib/jvm/java-17-openjdk-amd64


# Set working directory
WORKDIR /app

# Install Poetry
# RUN curl -sSL https://install.python-poetry.org | python3 -

# Add Poetry to PATH
# ENV PATH="/root/.local/bin:$PATH"

# Copy project files to container
COPY . .

# Install Python dependencies using Poetry
# RUN poetry install --no-dev

RUN pip install -r requirements.txt


# Create directories for Allure results and reports
RUN mkdir -p /app/allure-results /app/allure-report

# Set default command to run pytest and generate Allure report
CMD pytest -s --html=report.html && \
    echo "report was generated in report.html"
