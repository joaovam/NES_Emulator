
use std::collections::HashMap;

use crate::opcodes;


bitflags! {
    /// # Status Register (P) http://wiki.nesdev.com/w/index.php/Status_flags
    ///
    ///  7 6 5 4 3 2 1 0
    ///  N V _ B D I Z C
    ///  | |   | | | | +--- Carry Flag
    ///  | |   | | | +----- Zero Flag
    ///  | |   | | +------- Interrupt Disable
    ///  | |   | +--------- Decimal Mode (not used on NES)
    ///  | |   +----------- Break Command
    ///  | +--------------- Overflow Flag
    ///  +----------------- Negative Flag
    ///
    pub struct CpuFlags: u8 {
        const CARRY             = 0b00000001;
        const ZERO              = 0b00000010;
        const INTERRUPT_DISABLE = 0b00000100;
        const DECIMAL_MODE      = 0b00001000;
        const BREAK             = 0b00010000;
        const BREAK2            = 0b00100000;
        const OVERFLOW          = 0b01000000;
        const NEGATIVE          = 0b10000000;
    }
}

const STACK: u16 = 0x0100;
const STACK_RESET: u8 = 0xfd;

pub struct CPU {
    pub register_a: u8,
    pub register_x: u8,
    pub register_y: u8,
    pub stack_pointer: u8,
    pub status: CpuFlags,
    pub program_counter: u16,
    memory: [u8; 0xFFFF],
}

#[derive(Debug)]
#[allow(non_camel_case_types)]
pub enum AddressingMode {
    Immediate,
    ZeroPage,
    ZeroPage_X,
    ZeroPage_Y,
    Absolute,
    Absolute_X,
    Absolute_Y,
    Indirect_X,
    Indirect_Y,
    NoneAddressing,
}

impl CPU {
    pub fn new() -> Self {
        CPU {
            register_a: 0,
            register_x: 0,
            register_y: 0,
            stack_pointer: STACK_RESET,
            status: CpuFlags::from_bits_truncate(0b100100),
            program_counter: 0,
            memory: [0; 0xFFFF],
        }
    }

    pub fn reset(&mut self) {
        self.register_a = 0;
        self.register_x = 0;
        self.register_y = 0;
        self.status = CpuFlags::from_bits_truncate(0b100100);
        self.stack_pointer = STACK_RESET;

        self.program_counter = self.mem_read_u16(0xFFFC);
    }

    pub fn load_and_run(&mut self, program: Vec<u8>) {
        self.load(program);
        self.reset();
        self.run()
    }

    pub fn load(&mut self, program: Vec<u8>) {
        self.memory[0x8000..(0x8000 + program.len())].copy_from_slice(&program[..]);
        self.mem_write_u16(0xFFFC, 0x8000);
    }

    pub fn run(&mut self) {
        let ref opcodes:HashMap<u8, &'static opcodes::OpCode> = *opcodes::OPCODES_MAP;

        loop {
            
            let code = self.mem_read(self.program_counter);

            self.program_counter += 1;
            let opcode = opcodes.get(&code).expect(&format!("{:x} was not recognized", code));
            match code {

                0x69 | 0x65 | 0x75 | 0x6D | 0x7D | 0x79 | 0x61 | 0x71 => self.adc(),

                0x29 | 0x25 | 0x35 | 0x2D | 0x3D | 0x39 | 0x21 | 0x31 => self.and(&opcode.mode),
                0x0a => self.asl_acc(),

                0x06 | 0x16 | 0x0E | 0x1E => {self.asl(&opcode.mode);},

                0x90 => self.branch(!self.status.contains(CpuFlags::CARRY)),
                0xB0 => self.branch(self.status.contains(CpuFlags::CARRY)),
                0xF0 => self.branch(self.status.contains(CpuFlags::ZERO)),

                0x24 | 0x2c => self.bit(&opcode.mode),

                0x30 => self.branch(self.status.contains(CpuFlags::NEGATIVE)),
                0xD0 => self.branch(!self.status.contains(CpuFlags::ZERO)),
                0x50 => self.branch(!self.status.contains(CpuFlags::OVERFLOW)),
                0x70 => self.branch(self.status.contains(CpuFlags::OVERFLOW)),
                0x18 => self.status.remove(CpuFlags::CARRY),
                0xD8 => self.status.remove(CpuFlags::DECIMAL_MODE),
                0x58 => self.status.remove(CpuFlags::INTERRUPT_DISABLE),
                0xB8 => self.status.remove(CpuFlags::OVERFLOW),
                0xC9 | 0xC5 | 0xD5 | 0xCD | 0xDD | 0xD9 | 0xC1 | 0xD1 => self.compare(&opcode.mode, self.register_a),

                0xE0 | 0xE4 | 0xEC => self.compare(&opcode.mode, self.register_x),

                0xC0 | 0xC4 | 0xCC => self.compare(&opcode.mode, self.register_y),

                0xC6 | 0xD6 | 0xCE | 0xDE => self.dec(&opcode.mode),

                0xCA => self.dex(),
                0x88 => self.dey(),

                0xa9 | 0xa5 | 0xb5 | 0xad | 0xbd | 0xb9 | 0xa1 | 0xb1 => {
                    self.lda(&opcode.mode);
                }

                0xe8 => self.inx(),

                0x38 => self.sec(),
                0xF8 => self.sed(),
                0x78 => self.sei(),
                
                //STA
                0x85 | 0x95 | 0x8d | 0x9d | 0x99 | 0x81 | 0x91  =>{
                    self.sta(&opcode.mode);
                },
                0x86 | 0x96 | 0x8E =>{
                    self.stx(&opcode.mode)
                }

                0x84 | 0x94 | 0x8c =>{
                    self.sty(&opcode.mode)
                },

                0xAA => self.tax(),
                0xA8 => self.tay(),
                0xBA => self.tsx(),
                0x8A => self.txa(),
                0x9A => self.txs(),
                0x98 => self.tya(),
                0x00 => return,
                _ => todo!(),
            }
            self.program_counter += (opcode.len - 1) as u16;
        }
    }

    fn adc(&mut self){//
        todo!()
    }

    fn and(&mut self, mode: &AddressingMode){
        let addr = self.get_operand_addresses(mode);
        let value = self.mem_read(addr);
        
        self.register_a = self.register_a & value;
        self.update_zeros_and_negative_flags(self.register_a);
    }

    fn asl_acc(&mut self){
        let mut  val = self.register_a;

        if val >> 7 == 1 {
            self.sec();
        }else{
            self.clc();
        }
        val = val << 1;
        self.register_a = val;
        self.update_zeros_and_negative_flags(self.register_a);
        
    }

    fn asl(&mut self, mode: &AddressingMode) -> u8{
        let addr = self.get_operand_addresses(mode);
        let mut val = self.mem_read(addr);
        if val >> 7 == 1 {
            self.sec();
        }else{
            self.clc();
        }
        val = val << 1;
        self.mem_write(addr, val);
        self.update_zeros_and_negative_flags(val);
        val

    }

    fn bit(&mut self, mode: &AddressingMode){
        let addr = self.get_operand_addresses(mode);
        let v = self.mem_read(addr);
        let and = v & self.register_a;

        if and == 0{
            self.status.insert(CpuFlags::ZERO)
        }else{
            self.status.remove(CpuFlags::ZERO)
        }

        self.status.set(CpuFlags::OVERFLOW, v & 0b0100_0000 > 0);
        self.status.set(CpuFlags::OVERFLOW, v & 0b1000_0000 > 0)

    }

    fn clc(&mut self){
        self.status.remove(CpuFlags::CARRY);
    }

    fn compare(&mut self, mode: &AddressingMode, compare_with: u8){
        let addr = self.get_operand_addresses(mode);
        let val = self.mem_read(addr);

        

        if val <= compare_with{
            self.status.insert(CpuFlags::CARRY);
        }
        self.update_zeros_and_negative_flags(val.wrapping_sub(compare_with));

    }
    fn dec(&mut self, mode: &AddressingMode){
        let addr = self.get_operand_addresses(mode);
        let mut val = self.mem_read(addr);

        val = val.wrapping_sub(1);
        self.update_zeros_and_negative_flags(val);
        self.mem_write(addr, val);
    }

    fn dex(&mut self){
        self.register_x = self.register_x.wrapping_sub(1);
        self.update_zeros_and_negative_flags(self.register_x);
    }

    fn dey(&mut self){
        self.register_y = self.register_y.wrapping_sub(1);
        self.update_zeros_and_negative_flags(self.register_y);
    }

    fn lda(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_addresses(mode);
        let value = self.mem_read(addr);
        self.register_a = value;
        self.update_zeros_and_negative_flags(self.register_a);
    }
    fn sec(&mut self){
        self.status.insert(CpuFlags::CARRY);
    }
    fn sed(&mut self){
        self.status.insert(CpuFlags::DECIMAL_MODE);
    }

    fn sei(&mut self){
        self.status.insert(CpuFlags::INTERRUPT_DISABLE);
    }

    fn sta(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_addresses(mode);
        self.mem_write(addr, self.register_a);
    }


    fn inx(&mut self) {
        self.register_x = self.register_x.wrapping_add(1);

        self.update_zeros_and_negative_flags(self.register_x);
    }

    fn stx(&mut self, mode: &AddressingMode){
        let addr = self.get_operand_addresses(mode);
        self.mem_write(addr, self.register_x);
    }

    fn sty(&mut self, mode: &AddressingMode){
        let addr = self.get_operand_addresses(mode);
        self.mem_write(addr, self.register_y);
    }
    fn tax(&mut self) {
        self.register_x = self.register_a;
        self.update_zeros_and_negative_flags(self.register_x);
    }
    fn tay(&mut self){
        self.register_y = self.register_a;
        self.update_zeros_and_negative_flags(self.register_y);
    }

    fn txa(&mut self){
        self.register_a = self.register_x;
        self.update_zeros_and_negative_flags(self.register_a);
    }

    fn tsx(&mut self){
        self.register_x = self.stack_pointer;
        self.update_zeros_and_negative_flags(self.register_x);
    }
    fn txs(&mut self){
        self.stack_pointer = self.register_x;
    }

    fn tya(&mut self){
        self.register_a = self.register_y;
        self.update_zeros_and_negative_flags(self.register_a);
    }

    fn mem_read_u16(&self, pos: u16) -> u16 {
        let lo = self.mem_read(pos) as u16;
        let hi = self.mem_read(pos + 1) as u16;
        (hi << 8) | (lo as u16)
    }

    fn branch(&mut self, condition:bool){
        if condition {
            let jump = self.mem_read(self.program_counter) as i8;

            let jump_addr = self.program_counter.wrapping_add(1).wrapping_add(jump as u16);
            self.program_counter = jump_addr;
        }
    }

    fn mem_write_u16(&mut self, pos: u16, data: u16) {
        let hi = (data >> 8) as u8;
        let lo = (data & 0xff) as u8;
        self.mem_write(pos, lo);
        self.mem_write(pos + 1, hi);
    }

    fn mem_read(&self, addr: u16) -> u8 {
        self.memory[addr as usize]
    }

    fn mem_write(&mut self, addr: u16, data: u8) {
        self.memory[addr as usize] = data;
    }

    fn update_zeros_and_negative_flags(&mut self, result: u8) {
        if result == 0 {
            self.status.insert(CpuFlags::ZERO);
        } else {
            self.status.remove(CpuFlags::ZERO);
        }

        if result & 0b1000_0000 != 0 {
            self.status.insert(CpuFlags::NEGATIVE);
        } else {
            self.status.remove(CpuFlags::NEGATIVE);
        }
    }

    fn get_operand_addresses(&self, mode: &AddressingMode) -> u16 {
        match mode {
            AddressingMode::Immediate => self.program_counter,
            AddressingMode::ZeroPage => self.mem_read(self.program_counter) as u16,
            AddressingMode::Absolute => self.mem_read_u16(self.program_counter),
            AddressingMode::ZeroPage_X => {
                let pos = self.mem_read(self.program_counter);
                let addr = pos.wrapping_add(self.register_x) as u16;
                addr
            }
            AddressingMode::ZeroPage_Y => {
                let pos = self.mem_read(self.program_counter);
                let addr = pos.wrapping_add(self.register_y) as u16;
                addr
            }
            AddressingMode::Absolute_X => {
                let base = self.mem_read_u16(self.program_counter);
                let addr = base.wrapping_add(self.register_x as u16);
                addr
            }
            AddressingMode::Absolute_Y => {
                let base = self.mem_read_u16(self.program_counter);
                let addr = base.wrapping_add(self.register_y as u16);
                addr
            }
            AddressingMode::Indirect_X => {
                let base = self.mem_read(self.program_counter);
                let ptr = base.wrapping_add(self.register_x);
                let lo = self.mem_read(ptr as u16);
                let hi = self.mem_read(ptr.wrapping_add(1) as u16);
                (hi as u16) << 8 | (lo as u16)
            }
            AddressingMode::Indirect_Y => {
                let base = self.mem_read(self.program_counter);
                let lo = self.mem_read(base as u16);
                let hi = self.mem_read(base.wrapping_add(1) as u16);
                let deref_base = (hi as u16) << 8 | (lo as u16);
                deref_base.wrapping_add(self.register_y as u16)
            }
            AddressingMode::NoneAddressing => {
                panic!("mode {:?} not supported", mode)
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    
    #[test]
    fn test_0xa9_lda_immediate_load_data() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![0xa9, 0x05, 0x00]);
        assert_eq!(cpu.register_a, 5);
        assert!(cpu.status & 0b0000_0010 == 0);
        assert!(cpu.status & 0b1000_0000 == 0);
    }

    #[test]
    fn test_0xa9_lda_zero_flag() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![0xa9, 0x00, 0x00]);
        assert!(cpu.status & 0b0000_0010 == 0b10);
    }

    #[test]
    fn test_0xaa_tax_move_a_to_x() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![0xa9, 0x0A,0xaa, 0x00]);

        assert_eq!(cpu.register_x, 10)
    }

    #[test]
    fn test_5_ops_working_together() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![0xa9, 0xc0, 0xaa, 0xe8, 0x00]);

        assert_eq!(cpu.register_x, 0xc1)
    }

    #[test]
    fn test_inx_overflow() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![0xa9, 0xff, 0xaa,0xe8, 0xe8, 0x00]);

        assert_eq!(cpu.register_x, 1)
    }

    #[test]
    fn test_lda_from_memory() {
        let mut cpu = CPU::new();
        cpu.mem_write(0x10, 0x55);

        cpu.load_and_run(vec![0xa5, 0x10, 0x00]);

        assert_eq!(cpu.register_a, 0x55);
    }
}
