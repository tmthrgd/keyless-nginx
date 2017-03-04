use nom::be_u16;

pub struct Certificates<'a> {
	pub leaf: &'a [u8],
	pub chain: Vec<&'a [u8]>,
}

named!(pub parse<Certificates>, do_parse!(
	leaf: length_bytes!(be_u16) >>
	chain: many0!(length_bytes!(be_u16)) >>
	(
		Certificates{
			leaf: leaf,
			chain: chain,
		}
	))
);
