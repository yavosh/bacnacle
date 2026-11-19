//! Exact hashes of both HTML views, observed with Debian clamd 1.4.3.
#[path = "../examples/compat_oracle/daemon.rs"]
mod daemon;
use std::{fs, io, path::Path};

struct Case {
    id: String,
    page: String,
    markup: String,
    text: String,
}

fn digest(bytes: &[u8]) -> io::Result<String> {
    Ok(format!(
        "{}:{}",
        barnacle::hash_reader(bytes)?.md5_hex(),
        bytes.len()
    ))
}

fn cases() -> io::Result<Vec<Case>> {
    let mut cases = Vec::new();
    for (id, page, markup, text) in [
        (
            "tag-endings",
            "<?sheet value?><?sheet value ?><?sheet val=a?><?sheet val='a'?><?sheet flag other?><table><input disabled/><input disabled /><input disabled='x'/><item name=value/><item name=value /><br/><br />Inventory</table>",
            br#"<?sheet value?><?sheet value ?><?sheet val=a?><?sheet val="a" ?><?sheet flag other?><table><input disabled/><input disabled /><input disabled="x" /><item name=value/><item name=value /><br/><br />inventory</table>"#.as_slice(),
            b" inventory ".as_slice(),
        ),
        (
            "spaced-attribute-endings",
            r#"<html><img alt='Two words'/><img alt='Deux mots ici'/><img alt="Deux mots ici" /><img alt='A&#32;B'/><?paper alt='Print this'?><?paper alt='Print this' ?>Report</html>"#,
            br#"<html><img alt="two words"/><img alt="deux mots ici'/><img alt="deux mots ici" /><img alt="a b" /><?paper alt="print this"?><?paper alt="print this" ?>report</html>"#.as_slice(),
            b" report ".as_slice(),
        ),
        (
            "office-paths",
            r#"<?xml version="1.0"?><table><row path='xl/workbook.xml' format='Word.Document' alt='HWPML report'/>Documents</table>"#,
            br#"<?xml version="1.0" ?><table><row path="xl/workbook.xml" format="word.document" alt="hwpml report"/>documents</table>"#.as_slice(),
            b" documents ".as_slice(),
        ),
        (
            "press",
            "<html><p>Research & Development & Publications.</p></html>",
            b"<html><p>research & development & publications.</p></html>".as_slice(),
            b" research development publications. ".as_slice(),
        ),
        (
            "names",
            "<html><p>Résumé &amp; Caf&eacute; &copy; 2026</p></html>",
            b"<html><p>r\xc3\xa9sum\xc3\xa9 & caf\xe9 \xa9 2026</p></html>",
            b" r\xc3\xc3sum\xc3\xc3 caf 2026 ",
        ),
        (
            "map",
            "<html><a href=\"/map?lat=1&lon=2\">Find room A&B</a></html>",
            b"<html><a href=\"/map?lat=1&lon=2\">find room a&b</a></html>",
            b" /map?lat=1&lon=2 find room a ",
        ),
        (
            "companies",
            "<html><p>AT&T and R&D. Stars &amp; Planets. One &amp two.</p></html>",
            b"<html><p>at&t and r&d. stars & planets. one &amp two.</p></html>",
            b" at and r . stars planets. one two. ",
        ),
        (
            "tools",
            "<html><p>5 &lt; 8 and 7 &gt; 3. Tool A&B; sales.</p></html>",
            b"<html><p>5 < 8 and 7 > 3. tool a&b; sales.</p></html>",
            b" 5 8 and 7 3. tool a sales. ",
        ),
        (
            "music",
            "<html><p>Dots &hellip; Euro &euro; Music &#9834; and Paris &#233;.</p></html>",
            b"<html><p>dots &#x2026; euro &#x20ac; music &#x266a; and paris \xe9.</p></html>",
            b" dots euro music and paris . ",
        ),
        (
            "query",
            "<html><a title='Arts &amp; Crafts' href='/A?First=Paris&Region_ID=North&amp;Owner=Us#Map'>Visitor Info</a></html>",
            b"<html><a title=\"arts & crafts' href=\"/a?first=paris&region_id=north&owner=us#map\">visitor info</a></html>",
            b" /A?First=Paris&region_id=North&Owner=Us#Map visitor info ",
        ),
        (
            "picture",
            "<html><img src=/Photo?Title=&eacute;&Fee=&euro;&Note=&#9834;><p>Gallery &COPY; 2026</p></html>",
            b"<html><img src=/photo?title=\xe9&fee=&#x20ac;&note=&#x266a;><p>gallery &copy; 2026</p></html>",
            b" /Photo?Title=\xe9&fee=&#x20ac;&note=j gallery 2026 ",
        ),
        (
            "absent",
            "<html><p>Upper &AMP; units &angst; &ohm; &epsi; &epsiv; &phiv; &lang;3&rang;. Empty &; and &NotEqualTilde;.</p></html>",
            b"<html><p>upper &amp; units &#x212b; &#x2126; &#x03f5; &#x03b5; &#x03c6; &#x2329;3&#x232a;. empty &; and &notequaltilde;.</p></html>",
            b" upper units 3 . empty and . ",
        ),
        (
            "department",
            "<html><a href=\"/Dept/First Second   Third&amp;Four\">News &amp; Events</a></html>",
            b"<html><a href=\"/dept/first second third&amp;four\">news & events</a></html>",
            b" /Dept/First Secon news events ",
        ),
        (
            "station",
            "<html><img src='/city?near=東京　駅' alt='Arts &amp; Crafts'><p>New gallery</p></html>",
            "<html><img src=\"/city?near=東京　\" alt=\"駅arts & crafts'><p>new gallery</p></html>".as_bytes(),
            " /city?near=東京　 new gallery ".as_bytes(),
        ),
        (
            "edition",
            "<html><p><p title=\"Part 1 &amp; Résumé\">Paris</p></p></html>",
            "<html><p><p title=\"part 1 &amp; résumé\">paris</p></p></html>".as_bytes(),
            b" paris ",
        ),
        (
            "later",
            "<html><a href=\"é\">R</a><img src=\"PHOTO\"></html>",
            "<html><a href=\"\">r</a><img src=\"éphoto\"></html>".as_bytes(),
            " r éPHOTO ".as_bytes(),
        ),
        (
            "international",
            "<html><a href=\"/résumé?x=é&B=é.\">Room</a></html>",
            "<html><a href=\"/résumé?x=&bé=é.\">room</a></html>".as_bytes(),
            " /résumé?x=&bé=é. room ".as_bytes(),
        ),
        (
            "tokyo",
            "<html><a href=\"/Résumé?Tokyo=東京\">Room</a></html>",
            "<html><a href=\"/résumé?tokyo=東\">room</a></html>".as_bytes(),
            " /Résumé?Tokyo=東 room ".as_bytes(),
        ),
        (
            "capture",
            "<html><a href='A&b=2 Test ABC'>Registration</a></html>",
            b"<html><a href=\"a&b=2 test abc'>registration</a></html>",
            b" A&b=2 Tes registration ",
        ),
    ] {
        cases.push(Case {
            id: id.into(),
            page: page.into(),
            markup: digest(markup)?,
            text: digest(text)?,
        });
    }

    // Pin both complete artifacts independently of the values in the runtime table.
    let mut directory = String::from("<html><p>Directory:");
    for (i, row) in include_str!("../src/objects/text/html/entities.txt")
        .lines()
        .enumerate()
    {
        directory.push_str(&format!(
            "[{i}]&{};",
            row.split_ascii_whitespace().next().unwrap()
        ));
    }
    directory.push_str("</p></html>");
    cases.push(Case {
        id: "directory".into(),
        page: directory,
        markup: "7d530a7201abfd0b875258b7d2b4afe8:7637".into(),
        text: "8416fec5b806d1c62c332691d1b5bf4a:3873".into(),
    });
    for n in [1021, 1022, 1023, 1024, 1025] {
        let letters = "U".repeat(n);
        let page = format!("<html><a href=\"{letters}&Z=Paris\">Room {n}</a></html>");
        let markup = page.to_ascii_lowercase();
        let url = format!("{letters}&z=Paris");
        let text = format!(" {} room {n} ", &url[..1022]);
        cases.push(Case {
            id: format!("url{n}"),
            page,
            markup: digest(markup.as_bytes())?,
            text: digest(text.as_bytes())?,
        });
        let page = format!("<html><p>A&{letters}BC; end {n}</p></html>");
        let markup = page.to_ascii_lowercase();
        let token = format!("{letters}BC");
        let retained = if token.len() <= 1024 {
            String::new()
        } else {
            format!("{}; ", token[1024..].to_ascii_lowercase())
        };
        let text = format!(" a {retained}end {n} ");
        cases.push(Case {
            id: format!("token{n}"),
            page,
            markup: digest(markup.as_bytes())?,
            text: digest(text.as_bytes())?,
        });
    }
    Ok(cases)
}

fn compare(exe: &Path) -> io::Result<()> {
    let root = tempfile::tempdir_in("/tmp")?;
    let db = root.path().join("db");
    fs::create_dir(&db)?;
    let cases = cases()?;
    for markup in [true, false] {
        let mut rules = String::new();
        for case in &cases {
            rules.push_str(&format!("{}:Page.{}.Text\n", case.text, case.id));
            if markup {
                rules.push_str(&format!("{}:Page.{}.Markup\n", case.markup, case.id));
            }
        }
        fs::write(db.join("pages.hdb"), rules)?;
        let config = root.path().join("config");
        let socket = root.path().join("sock");
        fs::write(
            &config,
            format!(
                "Foreground yes\nDatabaseDirectory {}\nLocalSocket {}\nDisableCache yes\n",
                db.display(),
                socket.display()
            ),
        )?;
        let _service = daemon::Daemon::start(exe, &config, &socket)?;
        for case in &cases {
            let response =
                daemon::unix_request(&socket, &daemon::stream_frame(case.page.as_bytes())?)?;
            let kind = if markup { "Markup" } else { "Text" };
            assert_eq!(
                response,
                format!("stream: Page.{}.{kind}.UNOFFICIAL FOUND\0", case.id),
                "{}",
                case.page
            );
        }
    }
    Ok(())
}

#[test]
fn html_entities() -> io::Result<()> {
    compare(Path::new(env!("CARGO_BIN_EXE_barnacle")))
}

#[test]
#[ignore = "requires pinned Debian clamd"]
fn stock_html_entities() -> io::Result<()> {
    compare(Path::new("/usr/sbin/clamd"))
}
