use image::{ImageBuffer, Luma, ImageOutputFormat};
use qrcode::QrCode;

pub fn uri_to_png_bytes(uri: &str, scale: u32) -> Result<Vec<u8>, String> {
    let code = QrCode::new(uri.as_bytes()).map_err(|e| e.to_string())?;
    let image = code.render::<Luma<u8>>().min_dimensions(256, 256).build();
    let scaled = scale_image(&image, scale);
    let mut buf: Vec<u8> = Vec::new();
    let mut cursor = std::io::Cursor::new(&mut buf);
    scaled.write_to(&mut cursor, ImageOutputFormat::Png).map_err(|e| e.to_string())?;
    Ok(buf)
}

fn scale_image(img: &ImageBuffer<Luma<u8>, Vec<u8>>, scale: u32) -> ImageBuffer<Luma<u8>, Vec<u8>> {
    if scale <= 1 { return img.clone(); }
    let (w, h) = img.dimensions();
    let (nw, nh) = (w * scale, h * scale);
    let mut out = ImageBuffer::new(nw, nh);
    for y in 0..h {
        for x in 0..w {
            let p = *img.get_pixel(x, y);
            for dy in 0..scale { for dx in 0..scale { out.put_pixel(x*scale+dx, y*scale+dy, p); } }
        }
    }
    out
}


