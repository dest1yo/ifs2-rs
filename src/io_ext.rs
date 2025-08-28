use crate::array_read_ext::ArrayReadExt;
use crate::struct_read_ext::StructReadExt;
use std::io::{self, Read, Seek, SeekFrom};

pub trait SeekReadExt: Seek + Read + StructReadExt + ArrayReadExt {
    fn read_struct_at<S: Copy + 'static>(&mut self, pos: u64) -> Result<S, io::Error> {
        self.seek(SeekFrom::Start(pos))?;
        self.read_struct::<S>()
    }

    fn read_array_at<R: Copy + 'static>(
        &mut self,
        pos: u64,
        length: usize,
    ) -> Result<Vec<R>, io::Error> {
        self.seek(SeekFrom::Start(pos))?;
        self.read_array(length)
    }
}

impl<T> SeekReadExt for T where T: Seek + Read + StructReadExt + ArrayReadExt {}
