from graphviz import Digraph

dot = Digraph(comment="Alamanas", format='png')

def parse_trace():
    with open('trace_0.out') as f:
        nodes = []
        edges = set()
        ip = '0x0'
        block = ''
        for line in f:
            # Cleanup the string
            line = line.replace('\x00', '').strip()
            # Jump taken
            if line[0] == "@":
                target = line[1:]
                # Found very first instruction
                if ip == '0x0':
                    ip = target
                    continue
                
                dot.node(ip, label=block)
                block = ''
                edges.add((ip, target))
                ip = target
            # Disasm instruction
            else:
                block += line
        dot.edges(list(edges))
                

if __name__ == "__main__":
    dot.attr('node', shape='box')
    parse_trace()
    dot.render('CFG.gv', view=True) 