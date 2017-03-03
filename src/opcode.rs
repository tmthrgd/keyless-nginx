#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum Op {
	// The range [0x0000, 0x0100) is for opcodes taken from Cloudflare's upstream.
	//
	// Decrypt data using RSA with or without padding
	RSADecrypt = 0x0001,
	RSADecryptRaw = 0x0008,

	// Sign data using RSA
	RSASignMD5SHA1 = 0x0002,
	RSASignSHA1 = 0x0003,
	RSASignSHA224 = 0x0004,
	RSASignSHA256 = 0x0005,
	RSASignSHA384 = 0x0006,
	RSASignSHA512 = 0x0007,

	// Sign data using RSA-PSS
	RSAPSSSignSHA256 = 0x0035,
	RSAPSSSignSHA384 = 0x0036,
	RSAPSSSignSHA512 = 0x0037,

	// Sign data using ECDSA
	ECDSASignMD5SHA1 = 0x0012,
	ECDSASignSHA1 = 0x0013,
	ECDSASignSHA224 = 0x0014,
	ECDSASignSHA256 = 0x0015,
	ECDSASignSHA384 = 0x0016,
	ECDSASignSHA512 = 0x0017,

	// Request a certificate and chain
	GetCertificate = 0x0020,

	// Encrypt a blob of data
	Seal = 0x0021,
	Unseal = 0x0022,

	// [Deprecated]: A test message
	Ping = 0x00F1,
	Pong = 0x00F2,

	// [Deprecated]: A verification message
	Activate = 0x00F3,

	// Response
	Response = 0x00F0,
	Error = 0x00FF,

	// The range [0x0100, 0xc000) is for opcodes from our protocol version.
	Ed25519Sign = 0x0101, /* Sign data using Ed25519
	                       *
	                       * The range [0xc000, 0xffff) is reserved for private opcodes. */
}
