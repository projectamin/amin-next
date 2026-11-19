//! The shop example — the Rust form of `Amin::Example::Shop`.
//!
//! A middle-position element filter spliced on `<shop:request>`/`<shop:action>`
//! in the app's own namespace (`urn:projectamin:example:shop`).  It swallows
//! the shop element and emits the canonical `ui:` IR one element at a time
//! (§4.6); the projection fleet turns each `ui:` element into real `html:*`
//! events and the serializer escapes them (§4.5 — one escaper, markup never
//! built from a string).
//!
//! Everything here — the CSS, [`money`], [`stock`], [`percent_encode`], the
//! page shells and the exact `ui:` element order — is the Perl filter's,
//! verbatim, because the two implementations must render byte-identical pages.

use std::collections::BTreeMap;
use std::collections::HashMap;

use amin_sax::SaxError;

use crate::app::Product;
use crate::store::Store;
use crate::ui_target::UiSink;

/// The CSS that rides the IR as a `ui:style` leaf (a `<style>` in HTML, a no-op
/// elsewhere).  Verbatim from `Amin::Example::Shop`, trailing newline included.
pub const CSS: &str = concat!(
    "body{font-family:system-ui,sans-serif;margin:0;background:#f6f7f9;color:#1a1d21}\n",
    "nav{display:flex;gap:1rem;padding:.75rem 1.25rem;background:#1a1d21}\n",
    "nav a{color:#f6f7f9;text-decoration:none;font-weight:600}\n",
    "main{max-width:60rem;margin:1.5rem auto;padding:0 1rem}\n",
    "article{background:#fff;border:1px solid #e3e6ea;border-radius:.5rem;padding:1rem}\n",
    ".grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(14rem,1fr));gap:1rem}\n",
    "table{width:100%;border-collapse:collapse;background:#fff}\n",
    "th,td{padding:.5rem .6rem;border-bottom:1px solid #e3e6ea;text-align:left}\n",
    "form{display:inline-flex;gap:.4rem;align-items:center}\n",
    "button{background:#0a5c2e;color:#fff;border:0;border-radius:.35rem;padding:.45rem .8rem;cursor:pointer}\n",
    "div[role=alert]{background:#fff4d6;border:1px solid #e0c060;padding:.75rem 1rem;border-radius:.5rem}\n",
    "a{color:#0a5c2e}\n",
);

/// The shop filter: reads the app's own element, writes the `ui:` IR.
///
/// It borrows the catalogue (read-only) and the session store (the cart lives
/// behind it, keyed by the session id the transport supplied — §4.7).
pub struct Shop<'a> {
    catalog: &'a [Product],
    store: &'a mut Store,
    sink: &'a mut dyn UiSink,
}

impl<'a> Shop<'a> {
    /// Build a filter that emits into `sink`, reading `catalog` and `store`.
    pub fn new(catalog: &'a [Product], store: &'a mut Store, sink: &'a mut dyn UiSink) -> Self {
        Self {
            catalog,
            store,
            sink,
        }
    }

    /// Handle a `<shop:request>` element (a GET route).
    ///
    /// # Errors
    /// Propagates a sink failure.
    pub fn request(&mut self, a: &HashMap<String, String>) -> Result<(), SaxError> {
        let route = a.get("route").map_or("catalog", String::as_str);
        let sid = a.get("sid").map_or("", String::as_str);
        let cart = self.cart(sid);
        match route {
            "product" => self.page_product(a, &cart),
            "cart" => self.page_cart(a, &cart),
            _ => self.page_catalog(&cart),
        }
    }

    /// Handle a `<shop:action>` element (a POST action): mutate the cart, then
    /// render it (a no-JS form POST receives a full page — §4.6).
    ///
    /// # Errors
    /// Propagates a sink failure.
    pub fn action(&mut self, a: &HashMap<String, String>) -> Result<(), SaxError> {
        let name = a.get("name").map_or("", String::as_str);
        let sku = a.get("sku").map_or("", String::as_str);
        let sid = a.get("sid").map_or("", String::as_str);
        let qty_raw = a.get("qty").map_or("", String::as_str);
        let mut cart = BTreeMap::new();

        if !sid.is_empty() {
            let updated = self.store.update(sid, |rec| {
                if name == "cart.add" && !sku.is_empty() {
                    let qty = if is_digits(qty_raw) && to_num(qty_raw) > 0.0 {
                        to_num(qty_raw) as u64
                    } else {
                        1
                    };
                    *rec.cart.entry(sku.to_string()).or_insert(0) += qty;
                } else if name == "cart.set_qty" && !sku.is_empty() {
                    let qty = if is_digits(qty_raw) { to_num(qty_raw) as u64 } else { 0 };
                    if qty > 0 {
                        rec.cart.insert(sku.to_string(), qty);
                    } else {
                        rec.cart.remove(sku);
                    }
                } else if name == "cart.remove" && !sku.is_empty() {
                    rec.cart.remove(sku);
                }
            });
            if let Some(rec) = updated {
                cart = rec.cart;
            }
        }
        self.page_cart(a, &cart)
    }

    /// The cart for `sid` (empty when there is no session record).
    fn cart(&self, sid: &str) -> BTreeMap<String, u64> {
        if sid.is_empty() {
            return BTreeMap::new();
        }
        self.store.get(sid).map_or_else(BTreeMap::new, |r| r.cart.clone())
    }

    // ── ui: IR emission ───────────────────────────────────────────────────

    fn ui_start(&mut self, ln: &str, attrs: &[(&str, &str)]) -> Result<(), SaxError> {
        self.sink.start(ln, attrs)
    }

    fn ui_end(&mut self, ln: &str) -> Result<(), SaxError> {
        self.sink.end(ln)
    }

    fn ui_text(&mut self, t: &str) -> Result<(), SaxError> {
        self.sink.text(t)
    }

    fn ui_void(&mut self, ln: &str, attrs: &[(&str, &str)]) -> Result<(), SaxError> {
        self.sink.void(ln, attrs)
    }

    fn ui_text_el(&mut self, text: &str) -> Result<(), SaxError> {
        self.ui_start("text", &[])?;
        self.ui_text(text)?;
        self.ui_end("text")
    }

    fn ui_cell(&mut self, text: &str) -> Result<(), SaxError> {
        self.ui_start("cell", &[])?;
        self.ui_text(text)?;
        self.ui_end("cell")
    }

    fn ui_head_cell(&mut self, text: &str) -> Result<(), SaxError> {
        self.ui_start("cell", &[("header", "1")])?;
        self.ui_text(text)?;
        self.ui_end("cell")
    }

    fn nav_home(&mut self) -> Result<(), SaxError> {
        self.ui_start("navigate", &[("to", "/"), ("title", "Back to catalogue")])?;
        self.ui_end("navigate")
    }

    fn hidden(&mut self, name: &str, value: &str) -> Result<(), SaxError> {
        self.ui_void("field", &[("type", "hidden"), ("name", name), ("value", value)])
    }

    // ── pages ─────────────────────────────────────────────────────────────

    fn page_catalog(&mut self, cart: &BTreeMap<String, u64>) -> Result<(), SaxError> {
        self.page_open("Shop — Catalogue", cart)?;
        self.ui_text_el("Catalogue")?;
        let catalog = self.catalog;
        if catalog.is_empty() {
            self.ui_text_el("No products.")?;
        } else {
            self.ui_start("grid", &[])?;
            for p in catalog {
                self.ui_start("card", &[])?;
                let href = format!("/product?sku={}", percent_encode(&p.sku));
                self.ui_start("navigate", &[("to", &href), ("title", &p.name)])?;
                self.ui_end("navigate")?;
                self.ui_text_el(&money(to_num(&p.price)))?;
                self.ui_text_el(&stock(&p.stock))?;
                self.ui_end("card")?;
            }
            self.ui_end("grid")?;
        }
        self.page_close()
    }

    fn page_product(
        &mut self,
        a: &HashMap<String, String>,
        cart: &BTreeMap<String, u64>,
    ) -> Result<(), SaxError> {
        let sku = a.get("sku").map_or("", String::as_str);
        let catalog = self.catalog;
        let product = catalog.iter().find(|p| p.sku == sku);
        let title = match product {
            Some(p) => format!("{} — Shop", p.name),
            None => "Unknown product — Shop".to_string(),
        };
        self.page_open(&title, cart)?;
        match product {
            None => {
                self.ui_start("alert", &[])?;
                self.ui_text(&format!("Unknown product: {sku}"))?; // escaped by the serializer
                self.ui_end("alert")?;
                self.nav_home()?;
            }
            Some(p) => {
                self.ui_text_el(&p.name)?;
                self.ui_text_el(&money(to_num(&p.price)))?;
                self.ui_text_el(&stock(&p.stock))?;
                self.ui_start("form", &[("method", "post"), ("action", "/cart")])?;
                self.hidden("axa.action", "cart.add")?;
                self.hidden("axa.param.sku", &p.sku)?;
                self.hidden("axa.csrf", a.get("csrf").map_or("", String::as_str))?;
                self.ui_start("button", &[("title", "Add to cart")])?;
                self.ui_end("button")?;
                self.ui_end("form")?;
                self.nav_home()?;
            }
        }
        self.page_close()
    }

    fn page_cart(
        &mut self,
        a: &HashMap<String, String>,
        cart: &BTreeMap<String, u64>,
    ) -> Result<(), SaxError> {
        self.page_open("Cart — Shop", cart)?;
        self.ui_text_el("Your cart")?;
        if cart.is_empty() {
            self.ui_text_el("Your cart is empty.")?;
            self.nav_home()?;
            return self.page_close();
        }

        let catalog = self.catalog;
        let csrf = a.get("csrf").map_or("", String::as_str);

        let rows: Vec<Row> = cart
            .iter()
            .map(|(sku, qty)| {
                let product = catalog.iter().find(|p| &p.sku == sku);
                let price = product.map_or(0.0, |p| {
                    if is_decimal(&p.price) {
                        to_num(&p.price)
                    } else {
                        0.0
                    }
                });
                let name = product.map_or_else(|| sku.clone(), |p| p.name.clone());
                let qty = *qty;
                Row {
                    sku: sku.clone(),
                    name,
                    price,
                    qty,
                    line: price * qty as f64,
                }
            })
            .collect();
        let mut total = 0.0_f64;
        for r in &rows {
            total += r.line;
        }

        self.ui_start("table", &[])?;
        self.ui_start("tr", &[])?;
        for h in ["Product", "Price", "Qty", "Total"] {
            self.ui_head_cell(h)?;
        }
        self.ui_start("cell", &[])?;
        self.ui_end("cell")?;
        self.ui_end("tr")?;

        for r in &rows {
            self.ui_start("tr", &[])?;
            self.ui_cell(&r.name)?;
            self.ui_cell(&money(r.price))?;
            self.ui_start("cell", &[])?;
            self.ui_start("form", &[("method", "post"), ("action", "/cart")])?;
            self.hidden("axa.action", "cart.set_qty")?;
            self.hidden("axa.param.sku", &r.sku)?;
            self.hidden("axa.csrf", csrf)?;
            let qty = r.qty.to_string();
            self.ui_void(
                "field",
                &[
                    ("type", "number"),
                    ("name", "axa.param.qty"),
                    ("value", &qty),
                    ("min", "0"),
                    ("max", "999"),
                ],
            )?;
            self.ui_start("button", &[("title", "Update")])?;
            self.ui_end("button")?;
            self.ui_end("form")?;
            self.ui_end("cell")?;
            self.ui_cell(&money(r.line))?;
            self.ui_start("cell", &[])?;
            self.ui_start("form", &[("method", "post"), ("action", "/cart")])?;
            self.hidden("axa.action", "cart.remove")?;
            self.hidden("axa.param.sku", &r.sku)?;
            self.hidden("axa.csrf", csrf)?;
            self.ui_start("button", &[("title", "Remove")])?;
            self.ui_end("button")?;
            self.ui_end("form")?;
            self.ui_end("cell")?;
            self.ui_end("tr")?;
        }

        self.ui_start("tr", &[])?;
        for _ in 0..3 {
            self.ui_start("cell", &[])?;
            self.ui_end("cell")?;
        }
        self.ui_cell(&money(total))?;
        self.ui_start("cell", &[])?;
        self.ui_end("cell")?;
        self.ui_end("tr")?;
        self.ui_end("table")?;
        self.ui_text_el("Checkout is not wired up in this first pass.")?;
        self.nav_home()?;
        self.page_close()
    }

    /// The page shell every page shares: `ui:app` → `ui:style` → `ui:toolbar`
    /// (`nav`) → `ui:scene` (`main`).
    fn page_open(&mut self, title: &str, cart: &BTreeMap<String, u64>) -> Result<(), SaxError> {
        self.ui_start("app", &[("title", title)])?;
        self.ui_start("style", &[])?;
        self.ui_text(CSS)?;
        self.ui_end("style")?;
        self.ui_start("toolbar", &[])?;
        self.ui_start("navigate", &[("to", "/"), ("title", "Catalogue")])?;
        self.ui_end("navigate")?;
        let label = format!("Cart ({})", cart.len());
        self.ui_start("navigate", &[("to", "/cart"), ("title", &label)])?;
        self.ui_end("navigate")?;
        self.ui_end("toolbar")?;
        self.ui_start("scene", &[])
    }

    fn page_close(&mut self) -> Result<(), SaxError> {
        self.ui_end("scene")?;
        self.ui_end("app")
    }
}

/// One rendered cart row, precomputed so the emit loop borrows nothing.
struct Row {
    sku: String,
    name: String,
    price: f64,
    qty: u64,
    line: f64,
}

/// `sprintf '$%.2f', 0 + $v` — a money string.
#[must_use]
pub fn money(v: f64) -> String {
    format!("${v:.2}")
}

/// `($n // '') =~ /^\d+$/ && $n > 0 ? "$n in stock" : 'Out of stock'`.
#[must_use]
pub fn stock(n: &str) -> String {
    if is_digits(n) && to_num(n) > 0.0 {
        format!("{n} in stock")
    } else {
        "Out of stock".to_string()
    }
}

/// Percent-encode every byte outside `[A-Za-z0-9_.\-~]` (≈ `_u`).
#[must_use]
pub fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// `^\d+$`.
fn is_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// `^-?\d+(?:\.\d+)?$`.
fn is_decimal(s: &str) -> bool {
    let b = s.as_bytes();
    let mut i = 0;
    if i < b.len() && b[i] == b'-' {
        i += 1;
    }
    let start = i;
    while i < b.len() && b[i].is_ascii_digit() {
        i += 1;
    }
    if i == start {
        return false;
    }
    if i < b.len() && b[i] == b'.' {
        i += 1;
        let fr = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        if i == fr {
            return false;
        }
    }
    i == b.len()
}

/// Perl's `0 + $s`: the leading numeric prefix, or `0`.
#[must_use]
pub fn to_num(s: &str) -> f64 {
    let t = s.trim_start();
    let b = t.as_bytes();
    let mut i = 0;
    if i < b.len() && (b[i] == b'+' || b[i] == b'-') {
        i += 1;
    }
    let int_start = i;
    while i < b.len() && b[i].is_ascii_digit() {
        i += 1;
    }
    let mut frac = i;
    if i < b.len() && b[i] == b'.' {
        i += 1;
        frac = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
    }
    if i == int_start || (i == frac && frac == int_start + 1) {
        // no digits consumed at all
        if int_start == frac {
            return 0.0;
        }
    }
    t[..i].parse::<f64>().unwrap_or(0.0)
}
