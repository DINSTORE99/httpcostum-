module.exports = {

  initialXor:
    Buffer.from(
      "e382e4b8adc386f09f9293",
      "hex"
    ),

  nonce:
    Buffer.alloc(8, 0xdb),

  keys: [
    "2be4342943c6f91ff58987f41a1aafd179eeb4e053f5cea55b11d6a7db58bd7d",
    "3380aa278b744ba5b529a7f32fa803e48749280dae378345d9b526cf1dbce372",
    "cea9305c95168b162a335b137c61983b8df54e6375da01136547890f14c5fac3",
    "4beeace0e42bae8f29470cf40cf2dfacd5f4e1f751912bf52e803c8c85792193",
    "f8e5f6ebea90558eb32229da24fd0fb7d813091dafe89bb2954fda33b4c60f63",
    "81342f558a6273bac4548d473f54c4ffc7c41747dee81369acab9c787d41ab9c",
    "45635e6fc70486e2fd10d3c2b4780f02d0b4c5f4aa929fc54f86bb8fa4417944",
    "3d632a251c9820f2baf83e15498d27548fc67921cb437f8ce48505989378adea"
  ].map(x => Buffer.from(x, "hex")),

  rstKeys: [
    "JN1k3YHc2.6_v235",
    "JN1k3YHc_2.7_v71",
    "JN1k3YHc2.7.ps69",
    "JN1k3YHc2.7.6950",
    "Jn1K3yHc2.8.ps08",
    "Jn1K3yHc2.9.ps6c",
    "Zk:L7>WKaiK*s9>D",
    "!<f!&WIlM**R.B0X",
    "b4a5opinx2uloec6"
  ],

  jklOld: Buffer.from([
    0xd5,0xd4,0xd3,0xd2,0xd1,
    0xd0,0xcf,0xce,0xcd,0xcc,
    0xbd,0xbc,0xbb,0xba,0xb9,
    0xb8,0xb7,0xb6,0xb5,0xb4
  ]),

  jklNew: Buffer.from([
    8,9,10,11,12,13,14,15,
    17,17,5,4,3,2,1,0,
    255,254,253,252
  ]),

  rstXor:
    Buffer.from(
      Array.from(
        {length:20},
        (_,i) => i + 2
      )
    ),

  braille:
    "⠁⠃⠉⠙⠑⠋⠛⠓⠊⠚⠅⠇⠍⠝⠕⠏⠟⠗⠎⠞⠥⠧⠺⠭⠽⠵⠼⠁⠼⠃⠼⠉⠼⠙⠼⠑⠼⠋⠼⠛⠼⠓⠼⠊⠼⠚",

  tokenMap: [
    "payload",
    "proxy",
    "lockAllConfig",
    "blockedByRoot",
    "expiryTime",
    "noteEnabled",
    "notes",
    "sshField",
    "mobileDataAndLockProvider",
    "unlockUserAndPass",
    "ovpnConfig",
    "ovpnUserAndPass",
    "sni",
    "unlockUserAndPass2",
    "unknown14",
    "blockedByHwid",
    "cloudconfig",
    "psiphon",
    "name",
    "blockArea",
    "connectionMode",
    "blockedByPassword",
    "unknown22",
    "extraSniffer",
    "psiphon2",
    "v2rayEnabled",
    "v2rayConfig",
    "version",
    "slowdnsEnabled",
    "slowdnsServer",
    "slowdnsPublickey",
    "dnsResolver"
  ]

};
