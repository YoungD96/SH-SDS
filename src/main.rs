mod util;
mod sysguard;

use std::io::{Write};
use std::fs::File;
use std::path::Path;

use tempfile;
use umya_spreadsheet;
use fltk::{app, prelude::*, window::Window, button::Button, frame::Frame, *};
use fltk::dialog::FileDialog;
use fltk_theme::{widget_themes, WidgetTheme, ThemeType};

const VERSION: &'static str = env!("CARGO_PKG_VERSION");

static WIN_WIDTH: i32 = 512;
static WIN_HEIGHT: i32 = 512;

fn text_area(text: &str) -> text::TextDisplay {
    let mut textbuf = text::TextBuffer::default();
    textbuf.set_text(text);
    let mut disp = text::TextDisplay::default();
    disp.set_buffer(textbuf);
    disp.set_text_size(10);
    disp
}

struct TableCell {
    val: String,
    size: i32,
}

impl TableCell {
    fn new<S>(val: S, size: i32) -> Self where S: AsRef<str> {
        let val = val.as_ref().to_string();
        TableCell {
            val,
            size,
        }
    }
}

enum TableBlockType {
    Row,
    Col,
}

fn table_block(cells: Vec<TableCell>, typ: TableBlockType) -> group::Flex {
    let mut block = match typ {
        TableBlockType::Col => group::Flex::default().column(),
        TableBlockType::Row => group::Flex::default().row(),
    };
    for cell in cells {
        let text = text_area(&cell.val);
        block.set_size(&text, cell.size);
    }
    block.end();
    block
}

fn compound_row(subject: Vec<TableCell>, chklst: Vec<TableCell>, comments: Vec<TableCell>) -> group::Flex {
    let mut row = group::Flex::default().row();

    // First column: Security type
    let sectype = table_block(subject, TableBlockType::Col);
    row.set_size(&sectype, 100);
    let pad = frame::Frame::default();
    row.set_size(&pad, 1);

    // Second column: Safety requirements
    let _secreq = table_block(chklst, TableBlockType::Col);
    let pad = frame::Frame::default();
    row.set_size(&pad, 1);

    // Third column: Safety remarks
    let mut seccmt = group::Flex::default().column();
    for comment in comments {
        let text = text_area(&comment.val);
        seccmt.set_size(&text, comment.size);
    }
    seccmt.end();
    row.set_size(&seccmt, 150);
    let pad = frame::Frame::default();
    row.set_size(&pad, 1);

    row.end();
    row
}

fn row(c1: TableCell, c2 :TableCell, c3: TableCell) -> group::Flex {
    compound_row(vec![c1], vec![c2], vec![c3])
}

fn host_security_panel(scanbtn: Button) -> group::Scroll {
    let cell_height = 45i32;
    let bar_width = 10;

    let mut scroll = group::Scroll::default().with_size(WIN_WIDTH, WIN_HEIGHT - 20);
    let mut parent = group::Flex::default_fill().column().with_size(WIN_WIDTH, cell_height * 25);

    let mut button_group = group::Flex::default_fill().row();
    let mut btn = Button::new(0, 0, 40, 40, "Export");
    btn.set_callback(move |_| {
        let mut dlg = dialog::FileDialog::new(dialog::FileDialogType::BrowseSaveFile);
        dlg.set_option(dialog::FileDialogOptions::SaveAsConfirm);
        dlg.show();
        let filename = dlg.filename().to_string_lossy().to_string();
        saveas(filename);
    });

    button_group.set_size(&btn, WIN_WIDTH / 2 - bar_width);
    let mut btn = Button::new(0, 0, 40, 40, "Back");
    {
        let mut scroll = scroll.clone();
        let mut scanbtn = scanbtn.clone();
        btn.set_callback(move |_| {
            scroll.hide();
            scanbtn.show();
        });
    }
    button_group.set_size(&btn, WIN_WIDTH / 2 - bar_width);
    button_group.end();
    parent.set_size(&button_group, 30);

    let cell = sysguard::GuardItem::OS.check();
    let r = row(
        TableCell::new(cell.get("A4"), cell_height),
        TableCell::new(cell.get("B4"), cell_height),
        TableCell::new("", cell_height),
    );
    parent.set_size(&r, cell_height);

    let cell = sysguard::GuardItem::IP.check();
    let r = row(
        TableCell::new(cell.get("A5"), cell_height),
        TableCell::new(cell.get("B5"), cell_height),
        TableCell::new("", cell_height),
    );
    parent.set_size(&r, cell_height);

    let cell = sysguard::GuardItem::UserMgmt.check();
    let r = compound_row(
        vec![
            TableCell::new(cell.get("A8"), cell_height * 4),
        ],
        vec![
            TableCell::new(cell.get("B8"), cell_height * 2),
            TableCell::new(cell.get("B9"), cell_height * 2),
        ],
        vec![
            TableCell::new(cell.get("C8"), cell_height * 2),
            TableCell::new(cell.get("C9"), cell_height * 2),
        ],
    );
    parent.set_size(&r, cell_height * 4);

    let cell = sysguard::GuardItem::PasswdComplexity.check();
    let r = row(
        TableCell::new(cell.get("A10"), cell_height * 2),
        TableCell::new(cell.get("B10"), cell_height * 2),
        TableCell::new(cell.get("C10"), cell_height * 2),
    );
    parent.set_size(&r, cell_height * 2);


    let cell = sysguard::GuardItem::OperationTimeout.check();
    let r = row(
        TableCell::new(cell.get("A11"), cell_height * 1),
        TableCell::new(cell.get("B11"), cell_height * 1),
        TableCell::new(cell.get("C11"), cell_height * 1),
    );
    parent.set_size(&r, cell_height * 1);

    let cell = sysguard::GuardItem::Port.check();
    let r = row(
        TableCell::new(cell.get("A14"), cell_height * 2),
        TableCell::new(cell.get("B14"), cell_height * 2),
        TableCell::new(cell.get("C14"), cell_height * 2),
    );
    parent.set_size(&r, cell_height * 2);

    let cell = sysguard::GuardItem::Service.check();
    let r = row(
        TableCell::new(cell.get("A15"), cell_height * 4),
        TableCell::new(cell.get("B15"), cell_height * 4),
        TableCell::new(cell.get("C15"), cell_height * 4),
    );
    parent.set_size(&r, cell_height * 4);

    let cell = sysguard::GuardItem::Audit.check();
    let r = row(
        TableCell::new(cell.get("A19"), cell_height * 4),
        TableCell::new(cell.get("B19"), cell_height * 4),
        TableCell::new(cell.get("C19"), cell_height * 4),
    );
    parent.set_size(&r, cell_height * 4);

    let cell = sysguard::GuardItem::IPTables.check();
    let r = row(
        TableCell::new(cell.get("A21"), cell_height * 2),
        TableCell::new(cell.get("B21"), cell_height * 2),
        TableCell::new(cell.get("C21"), cell_height * 2),
    );
    parent.set_size(&r, cell_height * 2);

    let cell = sysguard::GuardItem::CommandHistory.check();
    let r = row(
        TableCell::new(cell.get("A25"), cell_height * 1),
        TableCell::new(cell.get("B25"), cell_height * 1),
        TableCell::new(cell.get("C25"), cell_height * 1),
    );
    parent.set_size(&r, cell_height * 1);

    parent.end();
    scroll.end();

    scroll.set_scrollbar_size(bar_width);
    scroll.set_type(group::ScrollType::Vertical);
    let mut scrollbar = scroll.scrollbar();
    scrollbar.set_type(valuator::ScrollbarType::VerticalNice);
    scrollbar.set_color(enums::Color::from_u32(0x757575));
    scrollbar.set_selection_color(enums::Color::Red);

    scroll
}

fn saveas(dst: String) -> Result<String, String> {
    let cells = vec![
        sysguard::GuardItem::OS,
        sysguard::GuardItem::IP,
        sysguard::GuardItem::UserMgmt,
        sysguard::GuardItem::PasswdComplexity,
        sysguard::GuardItem::OperationTimeout,
        sysguard::GuardItem::Port,
        sysguard::GuardItem::Audit,
        sysguard::GuardItem::IPTables,
        sysguard::GuardItem::Service,
        sysguard::GuardItem::CommandHistory,
    ];

    let dst = if !dst.ends_with(".xlsx") {
        dst + ".xlsx"
    } else {
        dst
    };
    let dst = Path::new(&dst);
    if dst.exists() {
        let _ = std::fs::remove_file(dst);
    }

    let tplbytes = include_bytes!("../assets/prototype_of_results_report.xlsx");
    let tmpdir = tempfile::tempdir().map_err(|e| format!("cannot create temporary directory: {:?}", e))?;
    let tplpath = tmpdir.path().join("tpl.xlsx");
    let mut tplfile = File::create(&tplpath).map_err(|e| format!("cannot create template file: {:?}", e))?;
    let _ = tplfile.write_all(&tplbytes[..]);

    let mut book = umya_spreadsheet::reader::xlsx::read(&tplpath).unwrap();
    let sheet = book.get_sheet_by_name_mut("Workstation").unwrap();
    for cell in cells {
        let r = cell.check();
        for (k, v) in r.mp.iter() {
            sheet.get_cell_mut(k.to_string()).set_value(v.to_string());
        }
    }

    if let Err(e) = umya_spreadsheet::writer::xlsx::write(&book, &dst) {
        return Err(format!("failed to write xlsx with error: {:?}", e));
    }
    Ok("save successfully".to_string())
}

fn main() {
    println!("Running sysguard version: {}", VERSION);

    let app = app::App::default();
    let widget_theme = WidgetTheme::new(ThemeType::AquaClassic);
    widget_theme.apply();

    let mut win = Window::default()
        .with_size(WIN_WIDTH, WIN_HEIGHT)
        .with_label("Security reinforcement inspection") 
        .center_screen();

    let mut scanbtn = Button::new(0, 0, 40, 40, "Scan").center_of(&win);
    let mut panel = host_security_panel(scanbtn.clone());
    panel.hide();
    let mut btndup = scanbtn.clone();
    scanbtn.set_callback(move |_| {
        panel.show();
        btndup.clone().hide();
    });

    win.set_color(enums::Color::from_rgb(250, 250, 250));
    win.end();
    win.show();

    app.run().unwrap();
}
