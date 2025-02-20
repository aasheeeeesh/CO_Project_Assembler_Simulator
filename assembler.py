class RISCVAssembler:
    def _init_(self):
        self.r_type_opcodes = {
            'add': '0110011', 'sub': '0110011', 'slt': '0110011',
            'srl': '0110011', 'or': '0110011', 'and': '0110011'
        }
        self.r_type_funct3 = {
            'add': '000', 'sub': '000', 'slt': '010',
            'srl': '101', 'or': '110', 'and': '111'
        }
        self.r_type_funct7 = {
            'add': '0000000', 'sub': '0100000', 'slt': '0000000',
            'srl': '0000000', 'or': '0000000', 'and': '0000000'
        }
        
        self.i_type_opcodes = {
            'lw': '0000011', 'addi': '0010011', 'jalr': '1100111'
        }
        self.i_type_funct3 = {
            'lw': '010', 'addi': '000', 'jalr': '000'
        }
        
        self.s_type_opcodes = {
            'sw': '0100011'
        }
        self.s_type_funct3 = {
            'sw': '010'
        }
        
        self.b_type_opcodes = {
            'beq': '1100011', 'bne': '1100011', 'blt': '1100011'
        }
        self.b_type_funct3 = {
            'beq': '000', 'bne': '001', 'blt': '100'
        }
        
        self.j_type_opcodes = {
            'jal': '1101111'
        }
        
        self.bonus_opcodes = {
            'rst': None,
            'halt': None
        }
        
        self.registers = {
            'zero': '00000', 'ra': '00001', 'sp': '00010', 'gp': '00011',
            'tp': '00100', 't0': '00101', 't1': '00110', 't2': '00111',
            's0': '01000', 'fp': '01000', 's1': '01001', 'a0': '01010', 
            'a1': '01011', 'a2': '01100', 'a3': '01101', 'a4': '01110',
            'a5': '01111', 'a6': '10000', 'a7': '10001', 's2': '10010',
            's3': '10011', 's4': '10100', 's5': '10101', 's6': '10110',
            's7': '10111', 's8': '11000', 's9': '11001', 's10': '11010',
            's11': '11011', 't3': '11100', 't4': '11101', 't5': '11110',
            't6': '11111'
        }
        
        self.virtual_halt = "00000000000000000000000001100011"

    def sign_extend(self, value, bits):
        """Sign extend a value to the specified number of bits"""
        sign_bit = 1 << (bits - 1)
        return (value & (sign_bit - 1)) - (value & sign_bit)
        
    def decimal_to_binary(self, decimal, width):
        if decimal < 0:
            decimal = (1 << width) + decimal
        return format(decimal & ((1 << width) - 1), f'0{width}b')
    
    def parse_register(self, reg):
        if reg in self.registers:
            return self.registers[reg]
        elif reg.startswith('x'):
            try:
                reg_num = int(reg[1:])
                if 0 <= reg_num <= 31:
                    return format(reg_num, '05b')
            except ValueError:
                pass
        raise ValueError(f"Invalid register: {reg}")
    
    def parse_immediate(self, imm):
        if imm.startswith('0x'):
            return int(imm, 16)
        elif imm.startswith('0b'):
            return int(imm, 2)
        else:
            return int(imm)
    
    def encode_r_type(self, instr, rd, rs1, rs2):
        opcode = self.r_type_opcodes[instr]
        funct3 = self.r_type_funct3[instr]
        funct7 = self.r_type_funct7[instr]
        
        rd_bin = self.parse_register(rd)
        rs1_bin = self.parse_register(rs1)
        rs2_bin = self.parse_register(rs2)
        
        binary = funct7 + rs2_bin + rs1_bin + funct3 + rd_bin + opcode
        return binary
    
    def encode_i_type(self, instr, rd, rs1, imm):
        opcode = self.i_type_opcodes[instr]
        funct3 = self.i_type_funct3[instr]
        
        rd_bin = self.parse_register(rd)
        rs1_bin = self.parse_register(rs1)
        
        if isinstance(imm, str) and imm.startswith('0x'):
            imm_val = int(imm, 16)
        else:
            imm_val = int(imm)
        
        imm_bin = self.decimal_to_binary(imm_val, 12)
        
        binary = imm_bin + rs1_bin + funct3 + rd_bin + opcode
        return binary
    
    def encode_s_type(self, instr, rs2, imm, rs1):
        opcode = self.s_type_opcodes[instr]
        funct3 = self.s_type_funct3[instr]
        
        rs1_bin = self.parse_register(rs1)
        rs2_bin = self.parse_register(rs2)
        
        if isinstance(imm, str):
            if imm.startswith('0x'):
                imm_val = int(imm, 16)
            else:
                imm_val = int(imm)
        else:
            imm_val = imm
            
        imm_bin = self.decimal_to_binary(imm_val, 12)
        imm_11_5 = imm_bin[0:7]
        imm_4_0 = imm_bin[7:12]
        
        binary = imm_11_5 + rs2_bin + rs1_bin + funct3 + imm_4_0 + opcode
        return binary
    
    def encode_b_type(self, instr, rs1, rs2, label, current_addr, label_map):
        opcode = self.b_type_opcodes[instr]
        funct3 = self.b_type_funct3[instr]
        
        rs1_bin = self.parse_register(rs1)
        rs2_bin = self.parse_register(rs2)
        
        if label in label_map:
            imm_val = label_map[label] - current_addr
        else:
            try:
                imm_val = self.parse_immediate(label)
            except ValueError:
                raise ValueError(f"Undefined label: {label}")
        
        if not -4096 <= imm_val <= 4095:
            raise ValueError(f"Branch offset out of range: {imm_val}")
        
        imm_bin = self.decimal_to_binary(imm_val, 13)
        
        imm_12 = imm_bin[0]
        imm_11 = imm_bin[1]
        imm_10_5 = imm_bin[2:8]
        imm_4_1 = imm_bin[8:12]
        
        binary = imm_12 + imm_10_5 + rs2_bin + rs1_bin + funct3 + imm_4_1 + imm_11 + opcode
        return binary
    
    def encode_j_type(self, instr, rd, label, current_addr, label_map):
        opcode = self.j_type_opcodes[instr]
        rd_bin = self.parse_register(rd)
        
        if label in label_map:
            imm_val = label_map[label] - current_addr
        else:
            try:
                imm_val = self.parse_immediate(label)
            except ValueError:
                raise ValueError(f"Undefined label: {label}")
        
        if not -1048576 <= imm_val <= 1048575:
            raise ValueError(f"Jump offset out of range: {imm_val}")
        
        imm_bin = self.decimal_to_binary(imm_val, 21)
        
        imm_20 = imm_bin[0]
        imm_10_1 = imm_bin[1:11]
        imm_11 = imm_bin[11]
        imm_19_12 = imm_bin[12:20]
        
        binary = imm_20 + imm_10_1 + imm_11 + imm_19_12 + rd_bin + opcode
        return binary
    
    def encode_virtual_halt(self):
        return self.virtual_halt

    def remove_comments(self, line):
        if '#' in line:
            return line.split('#', 1)[0]
        return line

    def tokenize_line(self, line):
        return line.replace(',', ' ').split()

    def process_line(self, line):
        line = self.remove_comments(line).strip()
        if not line:
            return None
        if ':' in line:
            parts = line.split(':', 1)
            if parts[1].strip() == "":
                return None  
            line = parts[1].strip()
        tokens = self.tokenize_line(line)
        if not tokens:
            return None
        return tokens

    def assemble_instruction_tokens(self, tokens, current_addr, label_map):
        instr = tokens[0].lower()

        if instr in self.r_type_opcodes:
            if len(tokens) != 4:
                raise ValueError(f"Invalid R-type instruction format: {' '.join(tokens)}")
            return self.encode_r_type(instr, tokens[1], tokens[2], tokens[3])
        elif instr in self.i_type_opcodes:
            if instr == 'lw':
                if len(tokens) != 3:
                    raise ValueError(f"Invalid load instruction format: {' '.join(tokens)}")
                offset_reg = tokens[2]
                if '(' in offset_reg and ')' in offset_reg:
                    offset, reg = offset_reg.split('(')
                    reg = reg.rstrip(')')
                    return self.encode_i_type(instr, tokens[1], reg, offset)
                else:
                    raise ValueError(f"Invalid load instruction format: {' '.join(tokens)}")
            elif instr == 'jalr':
                if len(tokens) != 4:
                    raise ValueError(f"Invalid jalr instruction format: {' '.join(tokens)}")
                return self.encode_i_type(instr, tokens[1], tokens[2], tokens[3])
            else:  
                if len(tokens) != 4:
                    raise ValueError(f"Invalid I-type instruction format: {' '.join(tokens)}")
                return self.encode_i_type(instr, tokens[1], tokens[2], tokens[3])

        elif instr in self.s_type_opcodes:
            if len(tokens) != 3:
                raise ValueError(f"Invalid S-type instruction format: {' '.join(tokens)}")
            offset_reg = tokens[2]
            if '(' in offset_reg and ')' in offset_reg:
                offset, reg = offset_reg.split('(')
                reg = reg.rstrip(')')
                return self.encode_s_type(instr, tokens[1], offset, reg)
            else:
                raise ValueError(f"Invalid store instruction format: {' '.join(tokens)}")

        elif instr in self.b_type_opcodes:
            if len(tokens) != 4:
                raise ValueError(f"Invalid B-type instruction format: {' '.join(tokens)}")
            return self.encode_b_type(instr, tokens[1], tokens[2], tokens[3], current_addr, label_map)

        elif instr in self.j_type_opcodes:
            if len(tokens) != 3:
                raise ValueError(f"Invalid J-type instruction format: {' '.join(tokens)}")
            return self.encode_j_type(instr, tokens[1], tokens[2], current_addr, label_map)

        elif instr == 'beq' and tokens[1] == 'zero' and tokens[2] == 'zero' and tokens[3] == '0':
            return self.encode_virtual_halt()
        else:
            raise ValueError(f"Unknown instruction: {instr}")
    
    def first_pass(self, assembly_lines):
        label_map = {}
        current_addr = 0
        
        for line in assembly_lines:
            line = line.strip()
            

            if not line or line.startswith('#'):
                continue
            

            if ':' in line:
                label, rest = line.split(':', 1)
                label = label.strip()
                label_map[label] = current_addr
                

                if rest.strip():
                    current_addr += 4
            else:
                current_addr += 4
        
        return label_map
    
    def assemble(self, input_file, output_file):
        with open(input_file, 'r') as f:
            assembly_lines = f.readlines()
        
        label_map = self.first_pass(assembly_lines)
        
        binary_lines = []
        current_addr = 0
        
        for orig_line in assembly_lines:
            tokens = self.process_line(orig_line)
            if tokens is None:
                continue
            try:
                binary = self.assemble_instruction_tokens(tokens, current_addr, label_map)
                binary_lines.append(binary)
                current_addr += 4
            except Exception as e:
                line_number = assembly_lines.index(orig_line) + 1
                print(f"Error at line {line_number}: {e}")
                print(f"  {orig_line.strip()}")
                continue
        
        if not binary_lines or binary_lines[-1] != self.encode_virtual_halt():
            print("Warning: Program does not end with Virtual Halt instruction")
        
        with open(output_file, 'w') as f:
            for binary in binary_lines:
                f.write(binary + '\n')
        
        print(f"Assembly completed: {len(binary_lines)} instructions generated")
        return len(binary_lines)

def main():
    import sys
    
    if len(sys.argv) != 3:
        print("--------------------")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    
    assembler = RISCVAssembler()
    try:
        num_instructions = assembler.assemble(input_file, output_file)
        print(f"Successfully assembled {num_instructions} instructions from {input_file} to {output_file}")
    except Exception as e:
        print(f"Assembly failed: {e}")
        sys.exit(1)

main()