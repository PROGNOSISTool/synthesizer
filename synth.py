import z3
import re
import json
import sys
import operator as oper
import graphviz as gv
import telnetlib
import random
import os
import time
import yaml

class TCPAbstraction:
        
        def __init__(self, auto, table):
                self.automaton = auto 
                self.path = table 
                self.inp_mask = lambda x: [x.get('seqNumber', -1), x.get('ackNumber', -1)]
                self.out_mask = lambda x: [x.get('seqNumber', -1), x.get('ackNumber', -1)]
                self.ignorable_inp = [True, True]
                self.ignorable_out = [False, False]
                self.ninps = 2
                self.nouts = 2

        def embed(self, label, inputs, outputs):
                inputs = inputs + [0]
                outputs = outputs + [0]
                inp, out = label.split(" / ")
                for ci in inputs:
                        inp = inp.replace('?', str(ci), 1)
                for co in outputs:
                        out = out.replace('?', str(co), 1)
                return (inp, out)
        

        def trace_and_mask(self, edges, whence):
              with open(whence) as f:
                      d = json.load(f)
                      for key in d:
                              input_text = re.match('\\(\\[([^\\]]*)', key)
                              if not input_text:
                                      continue
                              inp = input_text.groups()[0].split(', ')
                              state = 's0'
                              conc_trace = []
                              found = 0
                              for packet, v in enumerate(inp):
                                      print(v)
                                      for i, edge in enumerate(edges):
                                              f, l, t = edge
                                              print(l)
                                              if state == f and l.startswith(v):
                                                      state = t
                                                      conc_inp = self.inp_mask(d[key]['concreteInputs'][packet])
                                                      conc_out = self.out_mask(d[key]['concreteOutputs'][packet])
                                                      conc_trace.append((conc_inp, i, conc_out))
                                                      found += 1
                                                      break
                              if found == len(inp):
                                      yield conc_trace
      
        def evaluate(self, trace):
                tn = telnetlib.Telnet("127.0.0.1", "3333")
                try:
                        for inp, out in trace:
                                tn.write((inp+"\n").encode('ascii'))
                                p = tn.read_until(b"\n")        
                                if not str(p).startswith(out):
                                        return False
                        tn.write(b"RESET\n")
                except EOFError as exc: 
                        return False
                return True
        
class QUICAbstraction():

        def __init__(self, auto, table):
                self.automaton = auto 
                self.path = table 
                self.inp_mask = lambda x: [x.get('seqNumber', -1), x.get('ackNumber', -1)]
                self.out_mask = lambda x: [x.get('seqNumber', -1), x.get('ackNumber', -1)]
                self.ignorable_inp = [True, True]
                self.ignorable_out = [False, False]
                self.ninps = 2
                self.nouts = 2

        def embed(self, label, inputs, outputs):
                inputs = inputs + [0]
                outputs = outputs + [0]
                inp, out = label.split(" / ")
                for ci in inputs:
                        inp = inp.replace('?', str(ci), 1)
                for co in outputs:
                        out = out.replace('?', str(co), 1)
                return (inp, out)


        def trace_and_mask(self, edges, whence):
                with open(whence) as f:
                        d = json.load(f)
                        for key in d:
                                input_text = re.match('\\(\\[([^\\]]*)', key)
                                if not input_text:
                                        continue
                                inp = input_text.groups()[0].split(', ')
                                state = 's0'
                                conc_trace = []
                                found = 0
                                for packet, v in enumerate(inp):
                                        print(v)
                                        for i, edge in enumerate(edges):
                                                f, l, t = edge
                                                print(l)
                                                if state == f and l.startswith(v):
                                                        state = t
                                                        conc_inp = self.inp_mask(d[key]['concreteInputs'][packet])
                                                        conc_out = self.out_mask(d[key]['concreteOutputs'][packet])
                                                        conc_trace.append((conc_inp, i, conc_out))
                                                        found += 1
                                                        break
                                if found == len(inp):
                                        yield conc_trace

        def evaluate(self, trace):
                tn = telnetlib.Telnet("127.0.0.1", "3333")
                try:
                        for inp, out in trace:
                                tn.write((inp+"\n").encode('ascii'))
                                p = tn.read_until(b"\n")        
                                if not str(p).startswith(out):
                                        return False
                        tn.write(b"RESET\n")
                except EOFError as exc: 
                        return False
                return True


def flatten(xs):
        return sum(xs, [])

def counter():
        i = 0
        while True:
                yield i 
                i += 1

def indicate(xs, inds):
        n = len(xs)
        if inds == None:
                inds = [z3.FreshBool() for _ in range(n)]
        conj = z3.And(*[z3.Implies(inds[i], xs[i]) for  i in range(n)])
        return conj, inds

def one_of(inds):
        one_of_terms = [] 
        for i in range(len(inds)):
                term = []
                term.append(inds[i])
                for n in inds[:i]:
                        term.append(z3.Not(n))
                for n in inds[i+1:]:
                        term.append(z3.Not(n))
                one_of_terms.append(z3.And(term))
        one_of = z3.Or(one_of_terms)

        return z3.And(one_of)

def functions(left, rights, inds):
        funcs = []
        for r in rights:
                for op in [oper.eq, lambda x, y:  x == y+1]:
                        funcs.append(op(left, r))
        return indicate(funcs, inds)

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

def trace_and_mask(edges, whence, inp_mask, out_mask):
        with open(whence) as f:
                d = json.load(f)
                for key in d:
                        input_text = re.match('\\(\\[([^\\]]*)', key)
                        if not input_text:
                                continue
                        inp = input_text.groups()[0].split(', ')
                        state = 's0'
                        conc_trace = []
                        found = 0
                        for packet, v in enumerate(inp):
                                for i, edge in enumerate(edges):
                                        f, l, t = edge
                                        print(v)
                                        if state == f and l.startswith(v):
                                                state = t
                                                conc_inp = inp_mask(d[key]['concreteInputs'][packet])
                                                conc_out = out_mask(d[key]['concreteOutputs'][packet])
                                                conc_trace.append((conc_inp, i, conc_out))
                                                found += 1
                                                break
                        if found != 0:
                                print(conc_trace)
                        if found == len(inp):
                                yield conc_trace

def inputs_quic(x):
        prev = 2 
        stack = 0 
        for i in range(2, len(x)):
                if stack == 0 and x[i] == ',':
                        yield x[prev:i]
                        prev = i+1
                if stack == -1:
                        break
                if x[i] in "([":
                        stack += 1
                if x[i] in "])":
                        stack -= 1

# def trace_and_mask(edges, whence, inp_mask, out_mask):
#       with open(whence) as f:
#               d = json.load(f)
#               for key in d:
#                       inp = list(inputs_quic(key))
#                       print(key, inp)
#                       # input_text = re.match('\\(\\[([^\\]]*)', key)
#                       # if not input_text:
#                       #       continue
#                       # inp = input_text[0].split(', ')
#                       state = 's0'
#                       conc_trace = []
#                       found = 0
#                       for packet, v in enumerate(inp):
#                               for i, edge in enumerate(edges):
#                                       f, l, t = edge
#                                       # print(v)
#                                       if state == f and l.startswith(v):
#                                               state = t
#                                               conc_inp = inp_mask(d[key]['ConcreteInputs'][packet])
#                                               conc_out = out_mask(d[key]['ConcreteOutputs'][packet])
#                                               conc_trace.append((conc_inp, i, conc_out))
#                                               found += 1
#                                               break
#                       if found == len(inp) and found > 1:
#                               yield conc_trace

def enrich(traces, nedges, nregs, ninps, nouts, inp_ig, out_ig, ig_limit, negative = True):
        # inp_ignore = [[z3.FreshInt() if inp_ig[i] else 0 for i in range(ninps)] for _ in range(nedges)]
        upd_ignore = [[z3.FreshInt() for r in range(nregs)] for _ in range(nedges)]
        out_ignore = [[z3.FreshInt() if out_ig[i] else 0 for i in range(nouts)] for _ in range(nedges)]
        # ginds = [[None for _ in range(ninps)] for _ in range(nedges)]
        uinds = [[None for _ in range(nregs)] for _ in range(nedges)]
        oinds = [[None for _ in range(nouts)] for _ in range(nedges)]
        init_regs = [z3.FreshInt() for _ in range(nregs)]
        init_logic = []
        conjs = [] 
        for is_positive, trace in traces:
                trace_conjs = []
                n = len(trace)
                registers = [[z3.FreshInt() for _ in range(nregs)] for _ in range(n+1)]
                for r in range(nregs):
                        init_logic.append(init_regs[r] == registers[0][r])
                for i, packet in enumerate(trace):
                        inps, edge, outs = packet
                        # for j in range(ninps):
                        #       conj, ginds[edge][j] = functions(inps[j], registers[i], ginds[edge][j])
                        #       if inp_ig[j]:
                        #               conj = z3.Or(inp_ignore[edge][j] == 1, conj)
                        #       trace_conjs.append(conj)
                        for j in range(nregs):
                                conj, uinds[edge][j] = functions(registers[i+1][j], registers[i]+inps, uinds[edge][j])
                                conj = z3.Or(upd_ignore[edge][j] == 1, conj)
                                trace_conjs.append(conj)
                        for j in range(nouts):
                                conj, oinds[edge][j] = functions(outs[j], registers[i], oinds[edge][j])
                                if out_ig[j]:
                                        conj = z3.Or(out_ignore[edge][j] == 1, conj)
                                trace_conjs.append(conj)
                form = z3.And(*trace_conjs)
                if not is_positive:
                        conjs.append(z3.Not(form))
                else:
                        conjs.append(form)
        # all initial values are the same 
        init_logic = True #z3.And(*init_logic)

        # make sure only one indicator 
        one_ofs = z3.And(*[z3.And(*[z3.And(*[(one_of(v) if v else True) for v in inds]) for inds in edge]) for edge in [uinds, oinds]])

        # make sure ignores are one or zero
        igs = flatten(out_ignore) + flatten(upd_ignore)
        bounded = z3.And(*[z3.And(ig >= 0, ig <= 1) for ig in igs])
        total = sum(igs) <= ig_limit

        res = z3.And(*conjs, one_ofs, total, bounded, init_logic)
        return res, [uinds, oinds], [upd_ignore, out_ignore], init_regs

def cm(m, idx):
        if m == None:
                return None
        elif type(m) == list:
                if idx >= len(m):
                        return None
                return m[idx]
        elif type(m) == dict:
                if idx not in m:
                        return None 
                return m[idx]

def cmm(m, *args):
        v = m 
        for arg in args:
                v = cm(v, arg)
        return v

def ntz(m):
        if m == None:
                return 0
        else:
                return m

def zero_if_unevaluated(x):
        if type(x) == z3.z3.IntNumRef:
                return x
        else:
                return 0

def waitFile(file):
        while not os.path.isfile(file):
                time.sleep(1)
                print("Waiting...")
        return file 

class Synthesizer:

        def __init__(self, yamlPath):
                file = open(yamlPath, "r")
                objt = yaml.full_load(file)
                settings = objt['synthesizer']
                for key in ['protocol', 'dot', 'oracle_table']:
                        if key not in settings:
                                raise Exception("Expected {} under synthesizer in the config file".format(key))
                proto = settings['protocol']
                if proto == "TCP":
                        self.abstraction_constructor=TCPAbstraction
                elif proto == "QUIC":
                        self.abstraction_constructor=QUICAbstraction
                else:
                        raise Exception("Unknown protocol {} in config file".format(proto))

                self.dot_file = waitFile(settings['dot'])
                self.oracle_table = waitFile(settings['oracle_table'])

        def synthesize(self):
                limit_in  = lambda x: []
                limit_out = lambda x: [ntz(cmm(x, 0, 'Message', 'Frames', -1, 'Message', 'StreamDataLimit'))] #, 'Message', 'StreamDataLimit')]
                
                abstraction = self.abstraction_constructor(self.dot_file, self.oracle_table)
                edges = get_graph(abstraction.automaton)
                for edge in edges:
                        print(edge)
                
                ignorable_inp = [] # [True, True]
                ignorable_out = [False] #[False, False]
                traces = [(True, ex) for ex in abstraction.trace_and_mask(edges, abstraction.path)]
                print(traces)
                inc_edges = set()
                for b, trace in traces:
                        if not b:
                                continue
                        for _, l, _ in trace:
                                inc_edges.add(l)
                ign_edges = [edge for edge in range(len(edges)) if edge not in inc_edges]
                
                ninps = 0
                nouts = 1
                for trace in traces:
                        print(">>", trace)
                        for ig_sum in counter():
                                ig_sum = 10
                                for nreg in counter():
                                        print("ntraces", len(traces))
                                        print(">>", ig_sum, nreg)
                                        if nreg == 0:
                                                continue
                                        if nreg == 8:
                                                break
                                        machine, inds, igns, inits = enrich(traces, len(edges), nreg, abstraction.ninps, abstraction.nouts, abstraction.ignorable_inp, abstraction.ignorable_out, ig_sum)
                                        s = z3.Solver()
                                        s.add(machine)
                                        if s.check() == z3.sat:
                                                # print(">>", ig_sum, nreg)
                                                # break
                                                inputs = [z3.Int("i{}".format(i)) for i in range(abstraction.ninps)]
                                                registers = [z3.Int("r{}".format(i)) for i in range(nreg)]
                                                registersp = [z3.Int("r'{}".format(i)) for i in range(nreg)]
                                                outputs = [z3.Int("o{}".format(i)) for i in range(abstraction.nouts)]
                                                uinds, oinds = inds
                                                out_igns = igns
                                                m = s.model()
                                                for edge in range(len(edges)):
                                                        if edge in ign_edges:
                                                                continue
                                                        # gind = ginds[edge]
                                                        edge_str = []
                                                        # i = 0
                                                        # for inds, inp in zip(gind, inputs):
                                                        #       if ignorable_inp[i] and m.evaluate(inp_igns[edge][i]) == 1:
                                                        #               continue
                                                        #       else:
                                                        #               i += 1
                                                        #       conj, _ = functions(inp, registers, inds)
                                                        #       edge_str.append(m.evaluate(conj))
                                                        uind = uinds[edge]
                                                        for inds, reg in zip(uind, registersp):
                                                                conj, _ = functions(reg, registers+inputs, inds)
                                                                edge_str.append(m.evaluate(conj))
                                                        oind = oinds[edge]
                                                        i = 0
                                                        for inds, out in zip(oind, outputs):
                                                                if abstraction.ignorable_out[i] and m.evaluate(out_igns[edge][i] == 1):
                                                                        continue
                                                                else:
                                                                        i += 1
                                                                conj, _ = functions(out, registersp, inds)
                                                                edge_str.append(m.evaluate(conj))
                                                        f, l, t = edges[edge]
                                                        print('\t', f, '->', t, "[label =\"{}\"];".format(l + "," + '|'.join(map(str, edge_str))))
                                                print(inits)
                                                c = input()
                                                if c == "y":
                                                        gtno = []
                                                        new_traces = []
                                                        for positive, trace in [random.choice(traces)]:
                                                                inputs  = [[z3.FreshInt() for _ in range(abstraction.ninps)] for i in range(len(trace))]
                                                                output = [[z3.FreshInt() for _ in range(abstraction.nouts)] for i in range(len(trace))]
                                                                for s in [inputs, output]:
                                                                        for vector in s:
                                                                                for v in vector:
                                                                                        gtno.append(v >= -1)
                                                                new_trace = [(inputs[i], trace[i][1], output[i]) for i in range(len(trace))]
                                                                new_traces.append((not positive, trace, new_trace))
                                                        v, _, _, _ = enrich(map(lambda x: (x[0], x[2]), new_traces), len(edges), nreg, ninps, nouts, ignorable_inp, ignorable_out, ig_sum)
                                                        s = z3.Solver() 
                                                        s.add(z3.And(*gtno))
                                                        s.add(machine)
                                                        s.add(v)
                                                        if s.check() == z3.sat:
                                                                m = s.model()
                                                                for _, trace, new_trace in new_traces:
                                                                        inputs = [[zero_if_unevaluated(m.evaluate(i)) for i in pack[0]] for pack in new_trace]  
                                                                        output = [[zero_if_unevaluated(m.evaluate(o)) for o in pack[2]] for pack in new_trace]  
                                                                        conc_trace = [abstraction.embed(*t) for t in zip([edges[e][1] for _, e, _ in trace], inputs, output)]
                                                                        b = abstraction.evaluate(conc_trace)
                                                                        traces.append((b, new_trace))
                                                                        print(b, conc_trace)
                                                        else:
                                                                print("examples not found")
                                                        
                                        else:
                                                # print(v)
                                                # break
                                                print("unsat in {}...".format(nreg))
                
synth = Synthesizer("../config.yaml")
synth.synthesize()
