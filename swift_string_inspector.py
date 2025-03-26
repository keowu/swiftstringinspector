# (C) @Keowu - github.com/keowu/swiftstringinspector - 2025
import idaapi
import ida_kernwin
import idautils
import ida_ida
import struct
import idc
from PyQt5 import QtWidgets

# IDA CONSTANTS SUCKS. please Ifak do something.
NN_adr = 81
NN_mov = 80
NN_sub = 12
NM_x8 = 137
o_mem = 5
o_reg = 1
dt_qword = 7
# CONSTANTS
OFFSET_CONSTANT = 0x20
ADDRESSING_MASK = 0x8000000000000000
# DEBUG MODE
DEBUG_ENABLED = False

class SwiftInspectorChoose(idaapi.Choose):
    def __init__(self, title, n=12, flags=0, embedded=False, width=None, height=None, items_arg=None):
        super().__init__(title, [["Address", 10], ["Array Address", 30], ["Info", 40]],
                         flags=flags | idaapi.Choose.CH_RESTORE,
                         embedded=embedded, width=width, height=height)

        self.data = items_arg if items_arg is not None else []

    def OnGetLine(self, n):
        return self.data[n]

    def OnGetSize(self):
        return len(self.data)

    def OnSelectLine(self, sel):
        idaapi.jumpto(int(self.data[sel][0], 16))

class SwiftStringInspectorForm(ida_kernwin.PluginForm):
    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self.init_ui()

    def init_ui(self):
        layout = QtWidgets.QVBoxLayout()
        self.btnInspectSwiftString = QtWidgets.QPushButton("Inspect Swift::String")
        self.btnInspectSwiftArray = QtWidgets.QPushButton("Inspect Swift::String Array")
        self.btnInspectOptSwiftString = QtWidgets.QPushButton("Inspect Optimized Swift::String")
        self.btnAbout = QtWidgets.QPushButton("About")
        self.btnInspectSwiftString.clicked.connect(self.on_swift_string_inspector_click)
        self.btnInspectSwiftArray.clicked.connect(self.on_swift_string_array_inspector_click)
        self.btnInspectOptSwiftString.clicked.connect(self.on_opt_swift_string_click)
        self.btnAbout.clicked.connect(self.on_about)
        layout.addWidget(self.btnInspectSwiftString)
        layout.addWidget(self.btnInspectSwiftArray)
        layout.addWidget(self.btnInspectOptSwiftString)
        layout.addWidget(self.btnAbout)

        central_widget = QtWidgets.QWidget()
        central_widget.setLayout(layout)
        main_layout = QtWidgets.QVBoxLayout()
        main_layout.addWidget(central_widget)
        self.parent.setLayout(main_layout)

    def render_swift_chooser(self, items):
        SwiftInspectorChoose("Swift String Inspector", n=len(items), items_arg=items).Show(modal=True)

    def on_about(self):
        idaapi.info("Swift String Inspector was developer by @Keowu(www.github.com/keowu/swiftstringinspector)")

    def on_swift_string_inspector_click(self):
        self.render_swift_chooser(self.inspect_all_swift_strings())
        
    def on_swift_string_array_inspector_click(self):
        self.render_swift_chooser(self.inspect_all_swift_array_strings())
        
    def on_opt_swift_string_click(self):
        self.render_swift_chooser(self.inspect_all_swift_optn_swift_strings())
        
    def inspect_all_swift_strings(self):
        ea = ida_ida.inf_get_min_ea()
        end_ea = ida_ida.inf_get_max_ea()
        
        items = []

        while ea < end_ea:
            inst = idautils.DecodeInstruction(ea)
    
            if not inst:
                ea += 4 # Instructin size default lá do arm64
                continue

            # ADRL X8, some_ptr
            if inst.itype == NN_adr and \
                inst[0].reg == NM_x8 and \
                inst[1].type == idaapi.o_imm:
        
                inst2 = idautils.DecodeInstruction(ea + inst.size)
        
                # SUB X8, X8, OFFSET_CONSTANT
                if inst2.itype == NN_sub and \
                    inst2[0].reg == NM_x8 and \
                    inst2[2].value == OFFSET_CONSTANT:
                    string_bytes = idc.get_strlit_contents(inst[1].value, -1, idc.STRTYPE_C)
                    if string_bytes:
                        if DEBUG_ENABLED: print(f"(Swift::String) - 0x{ea:x} - 0x{inst[1].value - OFFSET_CONSTANT:x} - {string_bytes.decode()}")
                        items.append([f'0x{ea:x}', f'0x{inst[1].value:x}', f'{string_bytes.decode()}'])
                
            ea += inst.size
            
        return items
        
    def inspect_all_swift_array_strings(self):
        ea = ida_ida.inf_get_min_ea()
        end_ea = ida_ida.inf_get_max_ea()
        
        items = []
    
        while ea < end_ea:
        
            inst = idautils.DecodeInstruction(ea)
        
            if not inst:
                ea += 4
                continue
            
            # ADRL some_reg, some_off
            if inst.itype == NN_adr and inst[0].type == o_reg and inst[1].type == o_mem:
                value_swift = struct.unpack('<Q', idaapi.get_bytes(inst[1].value, 8))[0]
                # All array references use the same mask!
                if (value_swift & ADDRESSING_MASK) == ADDRESSING_MASK:
                    value_swift -= ADDRESSING_MASK
                    if (value_swift & 0xFF00000000000000) == 0: # The result needs to be always zero for be a valid swift array
                        if DEBUG_ENABLED: print(f"(Swift::String_SwiftArrayStorage_HEAD) - 0x{ea:x} -> p:[0x{value_swift:x}]")
                        items.append([f'0x{ea:x}', f'0x{value_swift:x}', 'Swift::String->SwiftArrayStorage->HEAD'])
            
            ea += inst.size
        
        return items

    def inspect_all_swift_optn_swift_strings(self):
        ea = ida_ida.inf_get_min_ea()
        end_ea = ida_ida.inf_get_max_ea()
    
        items = []
    
        while ea < end_ea:
        
            inst = idautils.DecodeInstruction(ea)
        
            if not inst:
                ea += 4
                continue
            
            # MOV X1, 0xIMM_with_8BYTES
            if inst.itype == NN_mov and inst[0].dtype == dt_qword and inst[1].dtype == dt_qword:
                big_endian = inst[1].value
                num_bytes = (big_endian.bit_length() + 7) // 8
                value_bytes = big_endian.to_bytes(num_bytes, byteorder='big')
                little_endian_value = int.from_bytes(value_bytes[::-1], byteorder='big')
                
                ascii_count = 0
                for i in range(num_bytes): 
                    if 0x00 <= (little_endian_value >> (8 * (num_bytes - i - 1))) & 0xff <= 0x7F: ascii_count += 1
            
                if ascii_count >= 4:
                    result_string = little_endian_value.to_bytes((little_endian_value.bit_length() + 7) // 8, byteorder='big').decode('ascii', errors='replace')
                    if DEBUG_ENABLED: print(f"IMM Optimized Swift::String: 0x{ea:x} 0x{inst[1].value:x} - 0x{little_endian_value:x} - {result_string}")
                    items.append([f'0x{ea:x}', f'0x{inst[1].value:x}', f'{result_string}'])
            
            ea += inst.size
            
        return items

    def Show(self):
        return ida_kernwin.PluginForm.Show(self, "Swift String Inspector", options=ida_kernwin.PluginForm.WOPN_PERSIST)

class SwiftInspectorPlugin(idaapi.plugmod_t):
    def __init__(self):
        super().__init__()
        self.form = None

    def run(self, arg):
        if self.form is None:
            self.form = SwiftStringInspectorForm()
            self.form.Show()

        return 0

class PluginEntry(idaapi.plugin_t):
    flags = idaapi.PLUGIN_MULTI
    comment = "A simple plugin to deal with strings, optimized strings and arrays while reversing Swift"
    wanted_name = "Swift String Inspector"
    wanted_hotkey = "Ctrl+0"

    def init(self):
        return SwiftInspectorPlugin()

def PLUGIN_ENTRY():
    return PluginEntry()
