//! Android boot header v2 images, which MediaTek devices such as chopin use
//! for their boot partition. The recovery lives in this image's ramdisk, so
//! changing it means rebuilding a v2 header, not a v3 one.

use abootimg_oxide::{binrw::io::Cursor, Header, HeaderV0, HeaderV0Versioned};
use anyhow::{anyhow, Context, Result};

/// A v2 boot image split into its header, kernel, ramdisk and DTB tail.
pub struct ImageV2 {
    header: HeaderV0,
    pub kernel: Vec<u8>,
    ramdisk: Vec<u8>,
    tail: Vec<u8>,
}

impl ImageV2 {
    /// Parse `bytes` as a v2 image; other header versions are left to
    /// `skyward_bootimg::BootImage`.
    pub fn parse(bytes: &[u8]) -> Result<Option<Self>> {
        let header = match Header::parse(&mut Cursor::new(bytes)).context("header")? {
            Header::V0(h) if h.header_version() == 2 => h,
            _ => return Ok(None),
        };
        let image_size = header.boot_image_size();
        let kernel = section(bytes, header.kernel_position(), header.kernel_size)?;
        let ramdisk = section(bytes, header.ramdisk_position(), header.ramdisk_size)?;
        let dtb_at = header.dtb_position().ok_or_else(|| anyhow!("v2 header has no DTB position"))?;
        let tail = bytes.get(dtb_at..image_size).context("dtb tail")?.to_vec();
        Ok(Some(Self { header, kernel, ramdisk, tail }))
    }

    pub fn ramdisk(&self) -> &[u8] {
        &self.ramdisk
    }

    pub fn set_ramdisk(&mut self, ramdisk: Vec<u8>) {
        self.ramdisk = ramdisk;
    }

    /// The boot image without its partition padding or AVB footer, ready to
    /// be handed to `avb::footed`.
    pub fn to_image_bytes(&self) -> Result<Vec<u8>> {
        let mut header = self.header.clone();
        header.kernel_size = u32::try_from(self.kernel.len()).context("kernel size")?;
        header.ramdisk_size = u32::try_from(self.ramdisk.len()).context("ramdisk size")?;
        // The DTB follows the ramdisk in the image; its header still names
        // the size and load address, which do not change here.
        if let HeaderV0Versioned::V2 { dtb_size, .. } = header.versioned {
            let _ = dtb_size;
        }
        let page = header.page_size as usize;
        let mut out = Vec::new();
        Header::V0(header).write(&mut out).context("write header")?;
        pad(&mut out, page);
        out.extend_from_slice(&self.kernel);
        pad(&mut out, page);
        out.extend_from_slice(&self.ramdisk);
        pad(&mut out, page);
        out.extend_from_slice(&self.tail);
        Ok(out)
    }
}

fn section(bytes: &[u8], at: usize, len: u32) -> Result<Vec<u8>> {
    bytes
        .get(at..at + len as usize)
        .map(<[u8]>::to_vec)
        .ok_or_else(|| anyhow!("section at {at} runs past the end of the image"))
}

fn pad(out: &mut Vec<u8>, page: usize) {
    let rest = out.len() % page;
    if rest != 0 {
        out.resize(out.len() + page - rest, 0);
    }
}

