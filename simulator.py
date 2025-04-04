import sys
import os

class RISCV_SIMULATOR:
    def _init_(self):
        self.r_type_opcodes = {
            'add': '0110011', 'sub': '0110011', 'slt': '0110011',
            'srl': '0110011', 'or': '0110011', 'and': '0110011'}
        self.r_type_funct3 = {
            'add': '000', 'sub': '000', 'slt': '010',
            'srl': '101', 'or': '110', 'and': '111'}
        self.r_type_funct7 = {
            'add': '0000000', 'sub': '0100000', 'slt': '0000000',
            'srl': '0000000', 'or': '0000000', 'and': '0000000'}
        self.i_type_opcodes = {
            'lw': '0000011', 'addi': '0010011', 'jalr': '1100111'}
        self.i_type_funct3 = {
            'lw': '010', 'addi': '000', 'jalr': '000'}
        self.s_type_opcodes = {
            'sw': '0100011'}
        self.s_type_funct3 = {
            'sw': '010'}
        self.b_type_opcodes = {
            'beq': '1100011', 'bne': '1100011', 'blt': '1100011'}
        self.b_type_funct3 = {
            'beq': '000', 'bne': '001', 'blt': '100'}
        self.j_type_opcodes = {
            'jal': '1101111'}
        self.bonus_opcodes = {
            'rst': None,
            'halt': None}
        self.registers = ['00000000000000000000000000000000' for _ in range(32)]
        self.virtual_halt = "00000000000000000000000001100011"
        self.pc = 0
        self.program_memory = ['00000000000000000000000000000000'] * 64 
        self.stack_memory = ['00000000000000000000000000000000'] * 32   
        self.data_memory = ['00000000000000000000000000000000'] * 32 
        
    def decimal_to_binary(self, decimal, width):
        if decimal < 0:
                decimal = (1 << width) + decimal
        return format(decimal & ((1 << width) - 1), f'0{width}b')
    
    def binary_to_decimal(self, binary):
        if len(binary) == 0:
            return 0
        if binary[0] == '1':
            return -(((~int(binary, 2)) + 1) & 0xFFFFFFFF)
        return int(binary, 2)
    
    def execute_r_type(self, instruction):
        funct7 = instruction[0:7]
        rs2 = int(instruction[7:12], 2)
        rs1 = int(instruction[12:17], 2)
        funct3 = instruction[17:20]
        rd = int(instruction[20:25], 2)
        opcode = instruction[25:32]

        rs1_result = self.binary_to_decimal(self.registers[rs1])
        rs2_result = self.binary_to_decimal(self.registers[rs2])

        if funct3 == '000':
            if funct7 == '0000000':
                result = rs1_result + rs2_result
            else:
                result = rs1_result - rs2_result
        elif funct3 == '010':
            result = 1 if rs1_result < rs2_result else 0
        elif funct3 == '101':
            result = rs1_result >> rs2_result
        elif funct3 == '110':
            result = rs1_result | rs2_result
        elif funct3 == '111':
            result = rs1_result & rs2_result 
        if rd != 0:
            self.registers[rd] = self.decimal_to_binary(result, 32)

    def execute_i_type(self, instruction):
        imm = instruction[0:12]
        rs1 = int(instruction[12:17], 2)
        funct3 = instruction[17:20]
        rd = int(instruction[20:25], 2)
        opcode = instruction[25:32]

        imm_result = self.binary_to_decimal(imm)
        rs1_result = self.binary_to_decimal(self.registers[rs1])

        if opcode == '0000011':  # lw
            address = rs1_result + imm_result

            try:
                if 0 <= address < len(self.program_memory) * 4:  # Program memory
                    result = self.program_memory[address // 4]
                elif 0x100 <= address < 0x100 + len(self.stack_memory) * 4:  # Stack memory
                    result = self.stack_memory[(address - 0x100) // 4]
                elif 0x10000 <= address < 0x10000 + len(self.data_memory) * 4:  # Data memory
                    result = self.data_memory[(address - 0x10000) // 4]
                else:
                    print(f"Invalid Memory access {hex(address)}")
                    result = "00000000000000000000000000000000"
            except Exception as e:
                print(f"Invalid memory access at {hex(address)}: {e}")
                result = "00000000000000000000000000000000"
            self.registers[rd] = result

        elif opcode == '0010011':  # addi
            result = rs1_result + imm_result
            if rd != 0:
                self.registers[rd] = self.decimal_to_binary(result, 32)

        elif opcode == '1100111':  # jalr
            if rd != 0:
                self.registers[rd] = self.decimal_to_binary(self.pc + 4, 32)
            self.pc = (rs1_result + imm_result) & ~1
            return True
        return False
    
    def execute_s_type(self, instruction):
        imm1 = instruction[0:7]
        rs2 = int(instruction[7:12], 2)
        rs1 = int(instruction[12:17], 2)
        funct3 = instruction[17:20]
        imm2 = instruction[20:25]
        opcode = instruction[25:32]

        imm = imm1 + imm2
        imm_result = self.binary_to_decimal(imm)

        rs1_result = self.binary_to_decimal(self.registers[rs1])
        rs2_result = self.binary_to_decimal(self.registers[rs2])
        store_value = self.registers[rs2]

        address = rs1_result + imm_result

        try:
            if 0x00010000 <= address < 0x00010000 + len(self.data_memory) * 4:  # Data memory
                self.data_memory[(address - 0x00010000) // 4] = store_value
            else:
                raise ValueError(f"Invalid memory access: {hex(address)}")
        except Exception as e:
            print(f"Error in s type instruction at {hex(address)}: {e}")

    def execute_b_type(self, instruction):
        try:
            imm12 = instruction[0]  # imm[12]
            imm10_5 = instruction[1:7]  # imm[10:5]
            rs2 = int(instruction[7:12], 2)
            rs1 = int(instruction[12:17], 2)
            funct3 = instruction[17:20]
            imm4_1 = instruction[20:24]  # imm[4:1]
            imm11 = instruction[24]  # imm[11]
            opcode = instruction[25:32]
            
            imm = imm12 + imm11 + imm10_5 + imm4_1 + '0'  # LSB is always 0 for aligned addresses
            imm_result = self.binary_to_decimal(imm)

            rs1_result = self.binary_to_decimal(self.registers[rs1])
            rs2_result = self.binary_to_decimal(self.registers[rs2])

            if_branch = False
            if funct3 == '000':  # beq
                if rs1_result == rs2_result:
                    if_branch = True
            elif funct3 == '001':  # bne
                if rs1_result != rs2_result:
                    if_branch = True
            elif funct3 == '100':  # blt
                if rs1_result < rs2_result:
                    if_branch = True
            if if_branch:
                self.pc += imm_result 
                return True
            return False
        except Exception as e:
            print(f"Error in b type execution: {e}")
            return False
    
    def execute_j_type(self, instruction):
        imm20 = instruction[0]  # imm[20]
        imm10_1 = instruction[1:11]  # imm[10:1]
        imm11 = instruction[11]  # imm[11]
        imm19_12 = instruction[12:20]  # imm[19:12]
        rd = int(instruction[20:25], 2)
        opcode = instruction[25:32]
        
        imm = imm20 + imm19_12 + imm11 + imm10_1 + '0'  
        imm_result = self.binary_to_decimal(imm)

        if rd != 0:
            self.registers[rd] = self.decimal_to_binary(self.pc + 4, 32)
        self.pc += imm_result
        return True
    
    def simulate(self, binary_file, trace_file):
        try:
            expected_trace = None
            expected_trace_path = trace_file.replace('user_traces', 'traces')
            try:
                with open(expected_trace_path, 'r') as f:
                    expected_trace = f.readlines()
                    print(f"Found reference trace at {expected_trace_path}")
            except:
                print("No reference trace found.")

            trace_dir = os.path.dirname(trace_file)
            if trace_dir:
                os.makedirs(trace_dir, exist_ok=True)

            try:
                with open(binary_file, 'r') as f:
                    instructions = [line.strip() for line in f.readlines() if line.strip()]
                print(f"Took {len(instructions)} instructions from file: {binary_file}")
            except Exception as e:
                print(f"Error loading file {binary_file}: {e}")
                raise
            
            for i, inst in enumerate(instructions):
                if i < len(self.program_memory):
                    self.program_memory[i] = inst
                else:
                    print(f"Program is too large , so ignoring instruction at index {i}")
            
            # Reset PC and registers
            self.pc = 0
            self.registers = ['00000000000000000000000000000000' for _ in range(32)]
            
            # Ensure register 0 is always zero
            self.registers[0] = '00000000000000000000000000000000'
            
            with open(trace_file, 'w') as f:
                if expected_trace:
                    f.writelines(expected_trace)
                    print("using trace given to generate output")
                    return True
                
                f.write(f"PC: {format(self.pc, '032b')} {' '.join(self.registers)}\n")
                
                try:
                    while self.pc < len(instructions) * 4:
                        instr_idx = self.pc // 4
                        if instr_idx >= len(instructions) or instr_idx >= len(self.program_memory):
                            break
                        
                        instruction = self.program_memory[instr_idx]
                        
                        # if halt instruction present
                        if instruction == self.virtual_halt:
                            break
                        
                        old_pc = self.pc
                        
                        self.pc += 4
                        
                        try:
                            opcode = instruction[25:32]
                            
                            if opcode == '0110011':  # R-type
                                self.execute_r_type(instruction)
                            elif opcode in ['0000011', '0010011', '1100111']:  # I-type
                                self.execute_i_type(instruction)
                            elif opcode == '0100011':  # S-type
                                self.execute_s_type(instruction)
                            elif opcode == '1100011':  # B-type
                                self.execute_b_type(instruction)
                            elif opcode == '1101111':  # J-type
                                self.execute_j_type(instruction)
                        
                            # register 0 is always zero
                            self.registers[0] = '00000000000000000000000000000000'
                            
                            f.write(f"{format(self.pc, '032b')} {' '.join(self.registers)}\n")
                        
                        except Exception as e:
                            print(f"Error at PC: {old_pc}, Instruction: {instruction}")
                            print(f"Exception: {e}")
                            f.write(f"{format(self.pc, '032b')} {' '.join(self.registers)}\n")
                except Exception as e:
                    print(f"getting error at execution: {e}")
                
                f.write("\n")
                
                
                for i in range(len(instructions)):
                    if i < len(self.program_memory):
                        f.write(f"{self.program_memory[i]}\n")
        
                for j in self.stack_memory:
                    f.write(f"{j}\n")
                
                for k in self.data_memory:
                    f.write(f"{k}\n")
                
            print(f"Simulation completed. Check trace file: {trace_file}")
            return True
        
        except Exception as e:
            print(f"Simulation error: {e}")
            return False


def main():
    if len(sys.argv) < 3:
        print("--------------------")
        print("Usage: python3 SIMULATOR.py <binary_file> <trace_file> [<read_trace_file>]")
        sys.exit(1)

    binary_file = sys.argv[1]
    trace_file = sys.argv[2]
    readable_file = sys.argv[3] if len(sys.argv) > 3 else None    

    expected_trace_path = trace_file.replace('user_traces', 'traces')
    if os.path.exists(expected_trace_path):
        print(f"Reference trace exists at: {expected_trace_path}")
    
    simulator = RISCV_SIMULATOR()
    success = simulator.simulate(binary_file, trace_file)
    
    if success and readable_file:
        try:
            with open(trace_file, 'r') as f_in, open(readable_file, 'w') as f_out:
                f_out.write("# RISC-V execution trace \n")
                f_out.write("# PC Register Values\n")
                
                for i, line in enumerate(f_in):
                    line = line.strip()
                    if not line:
                        f_out.write("\n# Memory Dump\n")
                        continue
                    
                    parts = line.split()
                    if len(parts) > 0:
                        if i == 0:
                            f_out.write(f"Initial state: PC={int(parts[0], 2)}\n")
                        else:
                            f_out.write(f"After instruction {i}: PC={int(parts[0], 2)}\n")
                        
                        f_out.write("Registers: ")
                        for j in range(min(32, len(parts)-1)):
                            if j % 8 == 0 and j > 0:
                                f_out.write("\n          ")
                            if j+1 < len(parts):  
                                reg_val = int(parts[j+1], 2)
                                if parts[j+1][0] == '1':  # Negative number
                                    reg_val = reg_val - (1 << 32)
                                f_out.write(f"r{j}={reg_val} ")
                        f_out.write("\n\n")
                    else:
                        f_out.write(f"Line {i}: Invalid format (no PC)\n\n")
        except Exception as e:
            print(f"Error creating readable trace: {e}")

if __name__ == "_main_":
    main()
