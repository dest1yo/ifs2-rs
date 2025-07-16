use crate::array_read_ext::ArrayReadExt;
use crate::string_read_ext::StringReadExt;
use crate::struct_read_ext::StructReadExt;
use std::io;
use std::io::{Read, Seek, SeekFrom};

pub trait SeekReadExt: Seek + Read + StructReadExt + StringReadExt + ArrayReadExt {
    // fn read_at(&mut self, pos: u64, buf: &mut [u8]) -> io::Result<usize> {
    //     self.seek(SeekFrom::Start(pos))?;
    //     self.read(buf)
    // }

    fn read_struct_at<S: Copy + 'static>(&mut self, pos: u64) -> Result<S, io::Error> {
        self.seek(SeekFrom::Start(pos))?;
        self.read_struct::<S>()
    }

    fn read_struct_at_index<S: Copy + 'static>(
        &mut self,
        pos: u64,
        index: u64,
    ) -> Result<S, io::Error> {
        self.seek(SeekFrom::Start(pos + index * size_of::<S>() as u64))?;
        self.read_struct::<S>()
    }

    fn read_null_terminated_string_at(&mut self, pos: u64) -> Result<String, io::Error> {
        self.seek(SeekFrom::Start(pos))?;
        self.read_null_terminated_string()
    }

    fn read_array_at<R: Copy + 'static>(
        &mut self,
        pos: u64,
        length: usize,
    ) -> Result<Vec<R>, io::Error> {
        self.seek(SeekFrom::Start(pos))?;
        self.read_array(length)
    }

    fn read_exact_at(&mut self, pos: u64, buf: &mut [u8]) -> Result<(), io::Error> {
        self.seek(SeekFrom::Start(pos))?;
        self.read_exact(buf)
    }
}

impl<T> SeekReadExt for T where T: Seek + Read + StructReadExt + StringReadExt + ArrayReadExt {}
