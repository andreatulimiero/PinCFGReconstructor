from graphviz import Digraph
from capstone import *
from collections import namedtuple

TRACE_LIMIT = 9999999

dot = Digraph(comment="Alamanas")
md = Cs(CS_ARCH_X86, CS_MODE_32)
Instruction = namedtuple('Instruction', 'address disasm')

text_instr = []
text_low = 0x401000
text_high = 0x40d730 

def disasm_text_section():
    instructions = []
    disasm_file = open("TEXT.disasm", "w+")
    with open('.text.dump', 'rb') as f:
        for i in md.disasm(f.read(), text_low):
            instructions += [Instruction(address=(i.address), disasm=i.mnemonic + ' ' + i.op_str)]
            print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str), file=disasm_file)
    return instructions


def getDisasmInRange(a, b):
    instructions = []
    for i in text_instr:
        if a <= i.address <= b:
            instructions += [i.disasm]
    if len(instructions) == 0:
        print('Nothing found from {} to {}'.format(hex(a), hex(b)))
    return instructions

def parse_trace():
    with open('trace_0.out') as f:
        lines_no = 0
        edges = set()
        last_ip = '0x0'
        for line in f:
            # Cleanup the string
            line = line.replace('\x00', '').strip()
            
            ip, target = line.split('@')
            # Very first instruction
            if ip == '':
                last_ip = target
                continue
            
            if not (text_low <= int(last_ip, 16) <= text_high):
                dot.node(last_ip, label='Stub')
            else:
                instr_in_range = getDisasmInRange(int(last_ip, 16), int(ip, 16))
                dot.node(last_ip, label='\n'.join(instr_in_range))
            edges.add((last_ip, target))
            last_ip = target

            if lines_no >= TRACE_LIMIT:
                break
            lines_no += 1

        dot.edges(list(edges))
                

if __name__ == "__main__":
    text_instr = disasm_text_section()
    dot.attr('node', shape='box')
    parse_trace()
    dot.render('CFG.gv', view=True) 