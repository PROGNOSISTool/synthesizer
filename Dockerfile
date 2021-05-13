FROM alpine
RUN apk add python3 py3-pip binutils gcc g++ make z3 graphviz
RUN pip3 install z3-solver graphviz pyyaml
ADD . /code
WORKDIR /code
CMD python3 synth.py
