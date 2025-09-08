FROM ubuntu:22.04

SHELL ["/bin/bash", "-c"]

RUN apt update
RUN apt -y install binutils

ADD https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh miniconda.sh
RUN bash ./miniconda.sh -b

COPY requirements.txt /opt/py225/
WORKDIR /opt/py225/
RUN <<EOF
source ~/miniconda3/bin/activate
conda create -y -n env python=3.13.5
conda activate env
echo Conda activated
pip install -r requirements.txt
EOF

COPY src /opt/py225/src
RUN <<EOF
source ~/miniconda3/bin/activate
conda activate env
pyinstaller src/py225d.py
pyinstaller src/py225.py
pyinstaller --distpath ./dist-onefile --onefile src/py225d.py
pyinstaller --distpath ./dist-onefile --onefile src/py225.py
EOF