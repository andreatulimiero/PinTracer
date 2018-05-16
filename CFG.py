import sys
from graphviz import Digraph

BRANCHES_LIMIT = 10000
branchesno = 0

if len(sys.argv) < 2:
  print("[x] Specify the name of the trace")
  sys.exit(1)

tracename = sys.argv[1]

g = Digraph('CFG')
g.attr('node', shape='box')

with open(tracename) as f:
  block = ''
  edges = set()
  address = '0x0'
  print('[*] Parsing ' + tracename)
  for line in f:
    # Cleanup the string
    line = line.replace('\x00', '').strip()
    # sys.exit(0)
    if line[0] == '@':
      g.node(address, label=block)
      edges.add((address, line[1:]))
      # g.edge(address, line[1:])
      address = line[1:]
      block = ''

      if branchesno >= BRANCHES_LIMIT:
        break
      branchesno += 1
    else:
      block += line + '\n'

  g.edges(list(edges))
  g.render('CFG_' + tracename, view=True)
