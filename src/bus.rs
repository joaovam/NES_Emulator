use crate::cartridge::Rom;
use crate::cpu::Mem;
use crate::ppu::NesPPU;
use crate::ppu::PPU;
pub struct Bus {
    cpu_vram: [u8; 2048],
    prg_rom: Vec<u8>,
    ppu: NesPPU,

    cycles: usize,
}

impl Bus {
    pub fn new(rom: Rom) -> Self {
        
        Bus {
            cpu_vram: [0; 2048],
            prg_rom: rom.prg_rom,
            ppu: NesPPU::new(rom.chr_rom, rom.screen_mirroring),
            cycles: 0,
        }
    }

    pub fn tick(&mut self, cycles: u8){
        self.cycles += cycles as usize;
        self.ppu.tick(cycles * 3);
    }

    fn read_prg_rom(&self, mut addr: u16) -> u8 {
        addr -= 0x8000;
        if self.prg_rom.len() == 0x4000 && addr >= 0x4000 {
            addr %= 0x4000;
        }
        self.prg_rom[addr as usize]
    }
}

const RAM: u16 = 0x0000;
const RAM_MIRROS_END: u16 = 0x1FFF;
const PPU_REGISTERS_MIRROR_END: u16 = 0x3FFF;

impl Mem for Bus {
    fn mem_read(&mut self, addr: u16) -> u8 {
        match addr {
            RAM..=RAM_MIRROS_END => {
                let mirror_down_addr = addr & 0b00000111_11111111;
                self.cpu_vram[mirror_down_addr as usize]
            }
            0x2000 | 0x2001 | 0x2003 | 0x2005 | 0x2006 | 0x4014 => {
                panic!("Attempt to read from write-only PPU address {:x}", addr);
            },
            0x2007 => self.ppu.read_data(),

            0x2008..=PPU_REGISTERS_MIRROR_END =>{
                let mirror_down_addr = addr & 0b00100000_00000111;
                self.mem_read(mirror_down_addr)

            }

            0x8000..=0xFFFF => self.read_prg_rom(addr),

            _ => {
                eprintln!("Ignoring mem access at {}", addr);
                0
            }
        }
    }

    fn mem_write(&mut self, addr: u16, data: u8) {
        match addr {
            RAM..=RAM_MIRROS_END => {
                let mirror_down_addr = addr & 0b11111111111;
                self.cpu_vram[mirror_down_addr as usize] = data;
            }
            0x2000 => self.ppu.write_to_ctrl(data),
            0x2001 => self.ppu.write_to_mask(data),
            0x2006 => self.ppu.write_to_ppu_addr(data),
            0x2007 => self.ppu.write_to_data(data),

            0x2008..=PPU_REGISTERS_MIRROR_END =>{
                let mirror_down_addr = addr & 0b00100000_00000111;
                self.mem_write(mirror_down_addr, data);
            },

            0x8000..=0xFFFF => {
                panic!("Attemp to write to Cartridge ROM space")
            },

            _ => {
                eprintln!("Ignoring mem access at {}", addr);
            }
        }
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use crate::cartridge::test;

    #[test]
    fn test_mem_read_write_to_ram() {
        let mut bus = Bus::new(test::test_rom());
        bus.mem_write(0x01, 0x55);
        assert_eq!(bus.mem_read(0x01), 0x55);
    }
}