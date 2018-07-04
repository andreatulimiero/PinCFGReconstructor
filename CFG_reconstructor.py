import json

from graphviz import Digraph
from capstone import *
from collections import namedtuple

TRACE_LIMIT = 9999999

dot = Digraph(comment="Alamanas")
md = Cs(CS_ARCH_X86, CS_MODE_32)
Instruction = namedtuple('Instruction', 'address disasm')

global report, images, sections
report = {}
images = {}
sections = {}

main_image = ''
text_instr = []
text_low = 0x0
text_high = 0x0

# Trying to understand why some parts are not found
global intervals
intervals = []
def updateIntervals(a, b):
    global intervals
    found = False
    for i in intervals:
        if i[0] <= a <= i[1]:
            found = True
            if b > i[1]:
                i[1] = b

        if i[0] <= b <= i[1]:
            found = True
            if a < i[0]:
                i[0] = a
    if not found:
        intervals += [[a, b]]

def load_report():
    global report, images, sections
    global text_low, text_high
    with open("report.json") as f:
        report = json.load(f)

    images = report["images"]
    main_image = report["main_image"]

    sections = report["sections"]
    text_section = report['text_section']
    text_low = sections[text_section]['address']
    text_size = sections[text_section]['size']
    text_low = text_low
    text_size = text_size
    text_high = text_low + text_size

def disasm_text_section():
    instructions = []
    disasm_file = open("TEXT.disasm", "w+")
    with open('.text.dump', 'rb') as f:
        for i in md.disasm(f.read(), text_low):
            instructions += [Instruction(address=(i.address), disasm=i.mnemonic + ' ' + i.op_str)]
            print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str), file=disasm_file)
    return instructions

def getDisasmInRange(a:int, b:int):
    instructions = []
    if (a > b) :
        print('Switched intervals {} {}'.format(a, b))
    for i in text_instr:
        if a <= i.address <= b:
            instructions += [i.disasm]
    if len(instructions) == 0:
        # print('Nothing found from {} to {}'.format(hex(a), hex(b)))
        updateIntervals(min(a, b), max(a, b))
    return instructions

def insertExternalStub(last_ip:str):
    found = False
    for name, mem_range in images.items():
        if mem_range['low_address'] <= int(last_ip, 16) <= mem_range['high_address']:
            found = True
            short_name = name[name.rfind('\\')+1:]
            dot.node(last_ip, label=short_name, shape='ellipse')
    if not found:
        dot.node(last_ip, label='Stub', shape='ellipse')

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
                insertExternalStub(last_ip)
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
    load_report()
    text_instr = disasm_text_section()
    dot.attr('node', shape='box')
    parse_trace()
    dot.render('CFG.gv', view=True)