FROM alpine
RUN apk add python3
RUN apk add py3-pip
RUN apk add binutils
RUN apk add gcc
RUN apk add g++
RUN apk add make
RUN pip3 install z3-solver
RUN pip3 install graphviz
ADD . .
