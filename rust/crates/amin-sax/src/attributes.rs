//! The attribute view — the Rust form of `org.xml.sax.Attributes` and
//! `org.xml.sax.AttributesImpl`.
//!
//! `org.xml.sax` exposes an `Attributes` as an *ordered list* addressed either
//! by index or, through a lookup, by qualified name (`qName`) or by the
//! (`uri`, `localName`) pair. [`Attributes`] is that interface;
//! [`AttributeList`] is the concrete, reader-built implementation.
//!
//! Namespace declarations (`xmlns`, `xmlns:p`) are **not** part of this list:
//! per the SAX2 namespace model they are delivered as
//! [`start_prefix_mapping`](crate::ContentHandler::start_prefix_mapping)
//! events instead of attributes.

/// One attribute: prefix, local name, resolved namespace, qualified name and
/// value.
///
/// `q_name` is the source spelling (`amin:id`); `prefix` and `local_name` are
/// its split; `namespace_uri` is what the prefix resolved to (`""` for an
/// unprefixed attribute, which never inherits the default namespace).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    /// Namespace prefix (`""` when the attribute is unprefixed).
    pub prefix: String,
    /// Local part of the qualified name.
    pub local_name: String,
    /// Resolved namespace URI (`""` when the attribute is unprefixed).
    pub namespace_uri: String,
    /// The qualified name as it appeared in the source.
    pub q_name: String,
    /// Entity-decoded value.
    pub value: String,
}

impl Attribute {
    /// The Clark-notation key `{uri}local` — the key Amin's Perl attribute
    /// maps are filed under, so a port can address an attribute identically.
    #[must_use]
    pub fn key(&self) -> String {
        format!("{{{}}}{}", self.namespace_uri, self.local_name)
    }
}

/// The read-only attribute view handed to
/// [`ContentHandler::start_element`](crate::ContentHandler::start_element)
/// (≈ `org.xml.sax.Attributes`).
///
/// Index accessors return `""` for an out-of-range index rather than panicking
/// (Java throws `ArrayIndexOutOfBoundsException`); lookups return `None`.
pub trait Attributes {
    /// The number of attributes.
    fn length(&self) -> usize;

    /// Namespace URI at `index`.
    fn uri(&self, index: usize) -> &str;

    /// Local name at `index`.
    fn local_name(&self, index: usize) -> &str;

    /// Qualified name at `index`.
    fn q_name(&self, index: usize) -> &str;

    /// Value at `index`.
    fn value(&self, index: usize) -> &str;

    /// DTD attribute type at `index`. Always `"CDATA"`: the reader does not
    /// process DTDs, so no attribute is ever declared otherwise.
    fn attr_type(&self, index: usize) -> &str {
        let _ = index;
        "CDATA"
    }

    /// Index of the attribute named `q_name`, if present.
    fn index_of_q_name(&self, q_name: &str) -> Option<usize>;

    /// Index of the attribute named (`uri`, `local_name`), if present.
    fn index_of(&self, uri: &str, local_name: &str) -> Option<usize>;

    /// Value of the attribute named `q_name`, if present.
    fn value_of_q_name(&self, q_name: &str) -> Option<&str> {
        self.index_of_q_name(q_name).map(|i| self.value(i))
    }

    /// Value of the attribute named (`uri`, `local_name`), if present.
    fn value_of(&self, uri: &str, local_name: &str) -> Option<&str> {
        self.index_of(uri, local_name).map(|i| self.value(i))
    }

    /// First value whose *local* name matches, whatever its namespace.
    ///
    /// This is the Amin convenience lookup: the Perl collectors key attributes
    /// by `{uri}local` but read them by local name (`_surface`, `Elt::_attr_flag`),
    /// so the same vocabulary table resolves the same way on both sides.
    fn value_of_local(&self, local_name: &str) -> Option<&str>;

    /// Whether there are no attributes.
    fn is_empty(&self) -> bool {
        self.length() == 0
    }
}

/// A reader-built [`Attributes`]: an ordered list of [`Attribute`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AttributeList {
    items: Vec<Attribute>,
}

impl AttributeList {
    /// An empty list.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A list with room for `n` attributes.
    #[must_use]
    pub fn with_capacity(n: usize) -> Self {
        Self { items: Vec::with_capacity(n) }
    }

    /// Append an attribute.
    pub fn push(&mut self, attr: Attribute) {
        self.items.push(attr);
    }

    /// Iterate the attributes in document order.
    pub fn iter(&self) -> std::slice::Iter<'_, Attribute> {
        self.items.iter()
    }
}

impl Attributes for AttributeList {
    fn length(&self) -> usize {
        self.items.len()
    }

    fn uri(&self, index: usize) -> &str {
        self.items.get(index).map_or("", |a| a.namespace_uri.as_str())
    }

    fn local_name(&self, index: usize) -> &str {
        self.items.get(index).map_or("", |a| a.local_name.as_str())
    }

    fn q_name(&self, index: usize) -> &str {
        self.items.get(index).map_or("", |a| a.q_name.as_str())
    }

    fn value(&self, index: usize) -> &str {
        self.items.get(index).map_or("", |a| a.value.as_str())
    }

    fn index_of_q_name(&self, q_name: &str) -> Option<usize> {
        self.items.iter().position(|a| a.q_name == q_name)
    }

    fn index_of(&self, uri: &str, local_name: &str) -> Option<usize> {
        self.items
            .iter()
            .position(|a| a.namespace_uri == uri && a.local_name == local_name)
    }

    fn value_of_local(&self, local_name: &str) -> Option<&str> {
        self.items
            .iter()
            .find(|a| a.local_name == local_name)
            .map(|a| a.value.as_str())
    }
}

impl<'a> IntoIterator for &'a AttributeList {
    type Item = &'a Attribute;
    type IntoIter = std::slice::Iter<'a, Attribute>;
    fn into_iter(self) -> Self::IntoIter {
        self.items.iter()
    }
}
