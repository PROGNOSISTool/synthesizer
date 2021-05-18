FROM alpine:3.13.5
RUN apk add python3 py3-pip binutils gcc g++ make graphviz
RUN pip3 install z3-solver graphviz pyyaml
ADD . /code
WORKDIR /code
ENTRYPOINT ["python3", "-u", "synth.py"]
