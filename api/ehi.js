const EHI = {
  // AES-256 Layer 1
  L1_KEY: Buffer.from(
    "7e1210f7aab956f7a668bda6e57feddb7f84ad840aef8d27b1b969959be3ab6c",
    "hex"
  ),

  // AES-128 Layer 2
  L2_KEY_STATIC: Buffer.from(
    "b2bc617c32d8b9eb1943a5ffa8051eea",
    "hex"
  ),

  // XXTEA master key
  EOO_MASTER_KEY: Buffer.from(
    "null=V5kU5+FFrY\u0000",
    "utf8"
  ),

  // BYPASS
  BYPASS_IVS: [
    Buffer.from(
      "221d572349555f1d112133236b1f4a3f",
      "hex"
    ),
    Buffer.from(
      "5543494c53443e3f4a6a4539384e776a",
      "hex"
    ),
    Buffer.from(
      "374c2541575e4d531a3c327b75431e5f",
      "hex"
    )
  ],

  // STANDARD
  STANDARD_IVS: [
    Buffer.from(
      "2c5d1147bbad422b3b334d4d235f1a53",
      "hex"
    ),
    Buffer.from(
      "522b01433a5e8b2fc7549e1ad368e541",
      "hex"
    ),
    Buffer.from(
      "337a1035aaedf3458ca167e92d74b839",
      "hex"
    )
  ],

  // Custom Base64 alphabet
  CUSTOM_ALPHABET:
    "RkLC2QaVMPYgGJW/A4f7qzDb9e+t6Hr0Zp8OlNyjuxKcTw1o5EIimhBn3UvdSFXs",

  // Standard Base64
  STANDARD_ALPHABET:
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
}
