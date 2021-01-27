import z3
import re
import json
import sys
import operator as oper
import graphviz as gv
import telnetlib
import random

class Automaton:

	def __init__(self, fdot = None):
		if fdot == None:
			self.accept = []
			self.nodes = []
			self.alphabet = []
			self.edges = []
			self.start = None
			return

		self.nodes = set()
		self.accept = set()
		self.alphabet = set()
	
		# get edges:
		self.edges = []
		with open(fdot) as f:
			for line in f:
				result = re.match('\t([^\\s]+) -> ([^\\s]+) \\[label="([^"]*)', line)
				if result:
					tup = result.groups()
					self.edges.append((tup[0], tup[2], tup[1]))
					self.alphabet.add(tup[2])
					self.nodes.add(tup[0])
					self.nodes.add(tup[1])

		self.start = 's0'
		self.accept = list(self.nodes.copy())
		self.nodes = list(self.nodes)
		self.alphabet = list(self.alphabet)
		self.edges = list(self.edges)

	def add_sink(self):
		ws = self.canonize()
		s = len(ws.nodes) 
		new_edges = []
		for node in ws.nodes:
			for lab in ws.alphabet:
				ok = False
				for f, l, _ in ws.edges:	
					if (f == node) and (l == lab):
						ok = True
						break
				if not ok:
					new_edges.append((node, lab, s))
		if len(new_edges) > 0:
			ws.nodes.append(s)
			ws.edges.extend(new_edges)
		return ws

	def copy(self):
		n = Automaton()
		n.start = self.start
		n.accept = [x for x in self.accept]
		n.nodes = [x for x in self.nodes]
		n.alphabet = [x for x in self.alphabet]
		n.edges = [x for x in self.edges]
		return n

	def complement(self):
		ws = self.add_sink()
		n = Automaton()
		n.start = self.start
		n.accept = [x for x in ws.nodes if x not in ws.accept]
		n.nodes = [x for x in ws.nodes]
		n.alphabet = [x for x in ws.alphabet]
		n.edges = [x for x in ws.edges]
		return n

	def union(self, other):
		n = Automaton()
		n.start = (self.start, other.start)
		n.accept = [(x, y) for x in self.nodes for y in other.nodes if (x in self.accept or y in other.accept)]
		n.nodes = [(x, y) for x in self.nodes for y in other.nodes]
		n.alphabet = list(set(self.alphabet).union(set(other.alphabet))) 
		n.edges = [((xf, yf), xl, (xt, yt)) for xf, xl, xt in self.edges for yf, yl, yt in other.edges if xl == yl]
		nc = n.canonize()
		return nc

	def intersection(self, other):
		return self.complement().union(other.complement()).complement()

	def canonize(self):
		m = {n: i for i, n in enumerate(self.nodes)}
		
		n = Automaton()
		n.start = m[self.start]
		n.accept = [m[x] for x in self.accept]
		n.nodes = [m[x] for x in self.nodes]
		n.alphabet = [x for x in self.alphabet]
		n.edges = [(m[f], l, m[t]) for f, l, t in self.edges]

		return n


	def get_trace(self, min_len=5):
		curr = self.start
		trace = []
		while len(trace) < min_len or curr not in self.accept:
			limited = [(l, t) for f, l, t in self.edges if (f == curr)]
			if len(limited) == 0:
				return None
			l, curr = random.choice(limited)	
			trace.append(l)
		return trace

	def show(self):
		for edge in self.edges:
			print(edge)
		print(self.accept)
		print(self.start)

a = Automaton("tcpTable.dot")
t = a.get_trace()
print(t)









