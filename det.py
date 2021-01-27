import numpy as np
import re

def get_graph(whence):
	# get edges:
	edges = []
	with open(whence) as f:
		for line in f:
			result = re.match('\t([^\\s]+) -> ([^\\s]+) \\[label="([^"]*)', line)
			if result:
				tup = result.groups()
				edges.append((tup[0], tup[2], tup[1]))
	return edges

def create_matrix(edges):
	labels = set()
	d = {}
	c = 0
	pairs = []
	for s, label, e in edges:
		labels.add(label)
		if s not in d:
			d[s] = c 
			c += 1
		if e not in d:
			d[e] = c 
			c += 1
		pairs.append((d[s], d[e]))

	m = np.zeros((c, c))
	for s, e in pairs:
		m[s, e] = 1 

	return m.T, len(labels)

def traces_up(matrix, n):
	c = matrix.shape[0]
	v = np.zeros((c))
	v[0] = 1 
	t = 0
	for i in range(n):
		t += sum(v)
		v = matrix.dot(v)
	return t

files = [
	"facebook.dot",
	"quic.dot",
	"quiche.dot",
	"tcp.dot",
]

for file in files:
	edges = get_graph(file)
	m, sz = create_matrix(edges)
	print(file, traces_up(m, 10), sz**10)