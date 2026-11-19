use super::udf;
use super::{
    ChildSink, Handling, Options, archive, iso, office, ole, onenote, pdf, rtf, swf, text,
};
use crate::body::{ObjectContext, Target};
use std::io;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum Parser {
    Archive,
    Rtf,
    Mail,
    Tnef,
    Uuencoded,
    Html,
    Utf16Html,
    Pdf,
    Ole2,
    Swf,
    OneNote,
    Image,
    Iso(iso::Layout),
    Udf,
    Text,
    None,
}

pub(super) struct FileType {
    pub name: &'static str,
    pub context: ObjectContext,
    pub parser: Parser,
}

// The pinned default file types omit these media and database formats from raw scans.
pub(super) fn ignored(bytes: &[u8]) -> bool {
    bytes.starts_with(b"ID3")
        || bytes.starts_with(b"OggS")
        || bytes.starts_with(b"SQLite format 3\0")
        || bytes.starts_with(b".RMF")
}

impl FileType {
    pub fn classify(
        bytes: &[u8],
        target: Option<Target>,
        sink: &mut dyn ChildSink,
    ) -> io::Result<Self> {
        if let Some(target) = target {
            return Ok(Self::typed(bytes, target, Parser::None));
        }
        if let Some(layout) = iso::Layout::recognize(bytes) {
            return Ok(Self::generic(
                bytes,
                text::file_type(bytes),
                Parser::Iso(layout),
            ));
        }
        if onenote::recognizes(bytes) {
            return Ok(Self::generic(bytes, "CL_TYPE_ONENOTE", Parser::OneNote));
        }
        if let Some(mut name) = archive::file_type(bytes) {
            if name == "CL_TYPE_ZIP" {
                name = office::classify(bytes, sink)?;
            }
            return Ok(Self::generic(bytes, name, Parser::Archive));
        }
        if bytes.starts_with(b"{\\rt") {
            return Ok(Self::generic(bytes, "CL_TYPE_RTF", Parser::Rtf));
        }
        if let Some(name) = text::container_type(bytes) {
            let parser = if name == "CL_TYPE_TNEF" {
                Parser::Tnef
            } else {
                Parser::Uuencoded
            };
            return Ok(Self::generic(bytes, name, parser));
        }
        let context = ObjectContext::raw(bytes);
        if matches!(context.target(), Target::Generic | Target::Mail) {
            match text::raw_target(bytes) {
                Some(Target::Html) if text::little_endian_html(bytes) => {
                    return Ok(Self::generic(
                        bytes,
                        "CL_TYPE_HTML_UTF16",
                        Parser::Utf16Html,
                    ));
                }
                Some(Target::Html) => return Ok(Self::typed(bytes, Target::Html, Parser::Html)),
                Some(Target::Mail) => return Ok(Self::typed(bytes, Target::Mail, Parser::Mail)),
                _ => {}
            }
        }
        let name = Self::name(context.target(), bytes);
        let parser = match context.target() {
            Target::Generic if name == "CL_TYPE_BINARY_DATA" && udf::recognized(bytes) => {
                Parser::Udf
            }
            Target::Pdf => Parser::Pdf,
            Target::Ole2 => Parser::Ole2,
            Target::Flash => Parser::Swf,
            Target::Graphics => Parser::Image,
            Target::Generic if name.starts_with("CL_TYPE_TEXT_") => Parser::Text,
            _ => Parser::None,
        };
        Ok(Self {
            name,
            context,
            parser,
        })
    }

    fn generic(bytes: &[u8], name: &'static str, parser: Parser) -> Self {
        Self {
            name,
            context: ObjectContext::typed(Target::Generic, bytes),
            parser,
        }
    }

    fn typed(bytes: &[u8], target: Target, parser: Parser) -> Self {
        Self {
            name: Self::name(target, bytes),
            context: ObjectContext::typed(target, bytes),
            parser,
        }
    }

    fn name(target: Target, bytes: &[u8]) -> &'static str {
        match target {
            Target::Html => "CL_TYPE_HTML",
            Target::Mail => "CL_TYPE_MAIL",
            Target::Pe => "CL_TYPE_MSEXE",
            Target::Elf => "CL_TYPE_ELF",
            Target::MachO => "CL_TYPE_MACHO",
            Target::Ole2 => "CL_TYPE_MSOLE2",
            Target::Flash => "CL_TYPE_SWF",
            Target::Graphics => match bytes {
                [0x89, b'P', b'N', b'G', ..] => "CL_TYPE_PNG",
                [b'G', b'I', b'F', ..] => "CL_TYPE_GIF",
                [0xff, 0xd8, 0xff, ..] => "CL_TYPE_JPEG",
                [b'I', b'I', 42, 0, ..] | [b'M', b'M', ..] => "CL_TYPE_TIFF",
                _ => "CL_TYPE_GRAPHICS",
            },
            Target::Pdf => "CL_TYPE_PDF",
            Target::Ascii => "CL_TYPE_TEXT_ASCII",
            Target::Generic => text::file_type(bytes),
            _ => "CL_TYPE_ANY",
        }
    }
}

impl Parser {
    pub fn disk_descriptor(self) -> Option<(usize, &'static str)> {
        match self {
            Self::Iso(layout) => Some((layout.descriptor_offset(), "CL_TYPE_ISO9660")),
            Self::Udf => Some((udf::RECOGNITION, "CL_TYPE_UDF")),
            _ => None,
        }
    }

    pub fn before_raw(
        self,
        bytes: &[u8],
        options: &Options,
        sink: &mut dyn ChildSink,
    ) -> io::Result<Handling> {
        match self {
            Self::Archive if options.scan_archive => archive::extract(bytes, sink),
            Self::Rtf if options.scan_archive => rtf::extract(bytes, sink),
            Self::Ole2 if options.scan_ole2 => ole::extract(bytes, sink),
            Self::Swf if options.scan_swf => swf::extract(bytes, sink),
            Self::OneNote if options.scan_onenote => onenote::extract(bytes, sink),
            // A broken-media check can precede the raw winner. The default
            // profile only computes image metadata for the logical matcher.
            Self::Image if options.scan_image && options.alert_broken_media => {
                Ok(Handling::Incomplete)
            }
            Self::Mail | Self::Tnef if options.scan_mail => text::before_raw(bytes, sink),
            Self::Html | Self::Utf16Html if options.scan_html => text::before_raw(bytes, sink),
            Self::Uuencoded => text::before_raw(bytes, sink),
            // These formats use the ordinary raw matcher after any enabled parser.
            Self::Archive
            | Self::Rtf
            | Self::Ole2
            | Self::Swf
            | Self::OneNote
            | Self::Image
            | Self::Iso(_)
            | Self::Udf
            | Self::Mail
            | Self::Tnef
            | Self::Html
            | Self::Utf16Html
            | Self::Pdf => Ok(Handling::Complete),
            Self::Text | Self::None => Ok(Handling::Unrecognized),
        }
    }

    pub fn after_raw(
        self,
        bytes: &[u8],
        options: &Options,
        sink: &mut dyn ChildSink,
    ) -> io::Result<Handling> {
        match self {
            Self::Pdf if options.scan_pdf => pdf::extract(bytes, sink),
            Self::Iso(layout) if options.scan_archive => iso::extract(bytes, layout, sink),
            Self::Udf if options.scan_archive => udf::extract(bytes, sink),
            Self::Text if options.scan_html => text::after_raw(bytes, sink),
            _ => Ok(Handling::Unrecognized),
        }
    }
}
