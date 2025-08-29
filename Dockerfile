FROM ubuntu:22.04

SHELL ["/bin/bash", "-c"]

COPY src /opt/py225/src
COPY requirements.txt /opt/py225/
WORKDIR /opt/py225/

RUN apt update
RUN apt -y install binutils

ADD https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh miniconda.sh
RUN bash ./miniconda.sh -b

RUN <<EOF
source ~/miniconda3/bin/activate
conda create -y -n env python=3.13.5
conda activate env
echo Conda activated
pip install -r requirements.txt
pyinstaller src/py225d.py
pyinstaller src/py225.py
EOF