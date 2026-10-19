import { expect, it } from "vitest";
import {
  RUST_DEMANGLE_INPUT_BYTES,
  RUST_DEMANGLE_OUTPUT_CHARS,
  classifyRustMangling,
  demangleRustSymbol,
} from "./RustDemangle.js";

/**
 * Golden corpus. v0 symbols are quoted byte-exact from the rustc book's
 * annotated v0 examples (doc.rust-lang.org/rustc/symbol-mangling/v0.html);
 * legacy symbols are quoted from rustc-demangle's legacy.rs test suite, with
 * the rustc book's Punycode identifier vectors expressed as v0 symbols. Where
 * this demangler pins a rendering choice beyond the non-normative suggestions
 * (lifetime indices, omitted disambiguators, and the always-applied legacy
 * hash trim that rustc applies only to the `#`-alternate form), the pinned
 * form is asserted.
 */
const CORPUS: readonly (readonly [mangled: string, demangled: string])[] = [
  ["_RNvCs15kBYyAo9fc_7mycrate7example", "mycrate::example"],
  ["RNvCs15kBYyAo9fc_7mycrate7example", "mycrate::example"],
  [
    "_RNvMsr_NtCs3ssYzQotkvD_3std4pathNtB5_7PathBuf3newCs15kBYyAo9fc_7mycrate",
    "<std::path::PathBuf>::new",
  ],
  ["_RNvMCs7qp2U7fqm6G_7mycrateNtB2_7Example3foo", "<mycrate::Example>::foo"],
  ["_RNvMs_Cs7qp2U7fqm6G_7mycrateNtB4_7Example3bar", "<mycrate::Example>::bar"],
  [
    "_RNvXCs15kBYyAo9fc_7mycrateNtB2_7ExampleNtB2_5Trait3foo",
    "<mycrate::Example as mycrate::Trait>::foo",
  ],
  [
    "_RNvYNtCs15kBYyAo9fc_7mycrate7ExampleNtB4_5Trait7exampleB4_",
    "<mycrate::Example as mycrate::Trait>::example",
  ],
  ["_RNCNvCsgStHSCytQ6I_7mycrate4main0B3_", "mycrate::main::{closure#0}"],
  ["_RNCNvCsgStHSCytQ6I_7mycrate4mains_0B3_", "mycrate::main::{closure#1}"],
  [
    "_RINvCsgStHSCytQ6I_7mycrate7examplelKj1_EB2_",
    "mycrate::example::<i32, 1>",
  ],
  [
    "_RINvCs7qp2U7fqm6G_7mycrate7exampleKy12345678_EB2_",
    "mycrate::example::<305419896>",
  ],
  [
    "_RINvCs7qp2U7fqm6G_7mycrate7exampleAtj8_EB2_",
    "mycrate::example::<[u16; 8]>",
  ],
  [
    "_RINvCs7qp2U7fqm6G_7mycrate7exampleTtlEEB2_",
    "mycrate::example::<(u16, i32)>",
  ],
  [
    "_RINvCs7qp2U7fqm6G_7mycrate7exampleNtB2_7ExampleBw_EB2_",
    "mycrate::example::<mycrate::Example, mycrate::Example>",
  ],
  [
    "_RINvMsY_NtCseXNvpPnDBDp_3std4pathNtB6_4Path3neweECs7qp2U7fqm6G_7mycrate",
    "<std::path::Path>::new::<str>",
  ],
  [
    "_RNvNvMCsd9PVOYlP1UU_7mycrateINtB4_7ExamplepKpE3foo14EXAMPLE_STATIC",
    "<mycrate::Example<_, _>>::foo::EXAMPLE_STATIC",
  ],
  [
    "_RNvNvNvCs7qp2U7fqm6G_7mycrate7EXAMPLE7___getit5___KEY$tlv$init",
    "mycrate::EXAMPLE::__getit::__KEY",
  ],
  [
    "_RNvNtNtCsgOH4LzxkuMq_7mycrateu8gdel_5qa6escher4bach",
    "mycrate::gödel::escher::bach",
  ],
  // The rustc book's Punycode table vectors, as v0 crate-root identifiers.
  // The `α_ω` encoding (`__ylb7e`) must carry the mandatory `_` separator
  // because the encoded bytes start with `_` (rustc emits it; the plain
  // `u7__ylb7e` spelling parses as a misaligned identifier instead).
  [
    "_RNvNtNtCsgOH4LzxkuMq_7mycrateu7___ylb7e6escher4bach",
    "mycrate::α_ω::escher::bach",
  ],
  ["_RNvC5crateu6f_5gaa", "crate::føø"],
  ["_RNvC5crateu6n84amf", "crate::铁锈"],
  ["_RNvC5crateu4fq9h", "crate::🤦"],
  ["_RNvC5crateu6_2xaedc", "crate::ρυστ"],
  [
    "_RNvC5crateu30____7hkackfecea1cbdathfdh9hlq6y",
    "crate::საჭმელად_გემრიელი_სადილი",
  ],
  [
    "_RINvCs7qp2U7fqm6G_7mycrate7exampleFG0_RL1_hRL0_tEuEB2_",
    "mycrate::example::<for<'a, 'b> fn(&'a u8, &'b u16)>",
  ],
  [
    "_RINvCs7qp2U7fqm6G_7mycrate7exampleDG_NtB2_5TraitEL_EB2_",
    "mycrate::example::<for<'a> dyn mycrate::Trait>",
  ],
  [
    "_RINvCs7qp2U7fqm6G_7mycrate7exampleFUKCxEzEB2_",
    'mycrate::example::<unsafe extern "C" fn(i64) -> !>',
  ],
  // rustc-demangle legacy.rs test vectors.
  ["_ZN4testE", "test"],
  ["_ZN4test1a2bcE", "test::a::bc"],
  ["ZN4testE", "test"],
  ["ZN13test$u20$test4foobE", "test test::foob"],
  ["ZN12test$RF$test4foobE", "test&test::foob"],
  ["_ZN4$RP$E", ")"],
  ["_ZN8$RF$testE", "&test"],
  ["_ZN8$BP$test4foobE", "*test::foob"],
  ["_ZN9$u20$test4foobE", " test::foob"],
  ["_ZN35Bar$LT$$u5b$u32$u3b$$u20$4$u5d$$GT$E", "Bar<[u32; 4]>"],
  ["_ZN13test$u20$test4foobE", "test test::foob"],
  ["_ZN12test$BP$test4foobE", "test*test::foob"],
  [
    "__ZN5alloc9allocator6Layout9for_value17h02a996811f781011E",
    "alloc::allocator::Layout::for_value",
  ],
  [
    "__ZN38_$LT$core..option..Option$LT$T$GT$$GT$6unwrap18_MSG_FILE_LINE_COL17haf7cb8d5824ee659E",
    "<core::option::Option<T>>::unwrap::_MSG_FILE_LINE_COL",
  ],
  [
    "__ZN4core5slice89_$LT$impl$u20$core..iter..traits..IntoIterator$u20$for$u20$$RF$$u27$a$u20$$u5b$T$u5d$$GT$9into_iter17h450e234d27262170E",
    "core::slice::<impl core::iter::traits::IntoIterator for &'a [T]>::into_iter",
  ],
  ["_ZN13_$LT$test$GT$E", "<test>"],
  ["_ZN28_$u7b$$u7b$closure$u7d$$u7d$E", "{{closure}}"],
  ["_ZN15__STATIC_FMTSTRE", "__STATIC_FMTSTR"],
  [
    "_ZN71_$LT$Test$u20$$u2b$$u20$$u27$static$u20$as$u20$foo..Bar$LT$Test$GT$$GT$3barE",
    "<Test + 'static as foo::Bar<Test>>::bar",
  ],
  [
    "_ZN151_$LT$alloc..boxed..Box$LT$alloc..boxed..FnBox$LT$A$C$$u20$Output$u3d$R$GT$$u20$$u2b$$u20$$u27$a$GT$$u20$as$u20$core..ops..function..FnOnce$LT$A$GT$$GT$9call_once17h69e8f44b3723e1caE",
    "<alloc::boxed::Box<alloc::boxed::FnBox<A, Output=R> + 'a> as core::ops::function::FnOnce<A>>::call_once",
  ],
  [
    "_ZN88_$LT$core..result..Result$LT$$u21$$C$$u20$E$GT$$u20$as$u20$std..process..Termination$GT$6report17hfc41d0da4a40b3e8E",
    "<core::result::Result<!, E> as std::process::Termination>::report",
  ],
  [
    "_ZN11utf8_idents157_$u10e1$$u10d0$$u10ed$$u10db$$u10d4$$u10da$$u10d0$$u10d3$_$u10d2$$u10d4$$u10db$$u10e0$$u10d8$$u10d4$$u10da$$u10d8$_$u10e1$$u10d0$$u10d3$$u10d8$$u10da$$u10d8$17h21634fd5714000aaE",
    "utf8_idents::საჭმელად_გემრიელი_სადილი",
  ],
  [
    "_ZN11issue_609253foo37Foo$LT$issue_60925..llv$u6d$..Foo$GT$3foo17h059a991a004536adE",
    "issue_60925::foo::Foo<issue_60925::llvm::Foo>::foo",
  ],
  // rustc-demangle demangle_without_hash vectors, with this demangler's
  // pinned always-applied legacy hash trim.
  ["_ZN3foo17h05af221e174051e9E", "foo"],
  ["_ZN3foo20h05af221e174051e9abcE", "foo"],
  ["_ZN3foo5h05afE", "foo"],
  ["_ZN17h05af221e174051e93fooE", "h05af221e174051e9::foo"],
  ["_ZN3foo16ffaf221e174051e9E", "foo::ffaf221e174051e9"],
  ["_ZN3foo17hg5af221e174051e9E", "foo::hg5af221e174051e9"],
  // Control codepoints and uppercase u-escape hex keep the escape verbatim.
  ["_ZN1a5c$u9$E", "a::c$u9$"],
  ["_ZN1a6c$u2A$E", "a::c$u2A$"],
  ["_ZN3std2io5stdio6_print17h0c4e6d4e9a8b7c6dE", "std::io::stdio::_print"],
  [
    "_ZN4core3ptr13drop_in_place17h1a2b3c4d5e6f7a8bE",
    "core::ptr::drop_in_place",
  ],
  [
    "_ZN4core6option15Option$LT$T$GT$6unwrap17hc0ffee0123456789E",
    "core::option::Option<T>::unwrap",
  ],
  [
    "_ZN5alloc3vec12Vec$LT$T$GT$3new17hdeadbeefdeadbeefE",
    "alloc::vec::Vec<T>::new",
  ],
  ["_ZN7example5STATEE", "example::STATE"],
  ["_ZN4demo12no$u20$spaceE", "demo::no space"],
  ["_ZN6my_lib4mainE", "my_lib::main"],
  ["_ZN4main17h45e8b8c6e3b6b5f0E", "main"],
];

it("demangles the complete golden corpus", () => {
  for (const [mangled, demangled] of CORPUS) {
    const result = demangleRustSymbol(mangled);
    expect(result, mangled).toEqual({
      demangled,
      mangled,
      format: classifyRustMangling(mangled),
      failure_reason: null,
    });
  }
});

it("keeps the legacy hash suffix trimmed and later segments intact", () => {
  const result = demangleRustSymbol(
    "_ZN6cratex15nested$LT$T$GT$9with_hash17habcdef0123456789E",
  );
  expect(result.demangled).toBe("cratex::nested<T>::with_hash");
});

it("classifies non-Rust names without attempting a scheme", () => {
  expect(classifyRustMangling("memcpy")).toBe("other");
  expect(classifyRustMangling("__ZN4main17h45e8b8c6e3b6b5f0E")).toBe("legacy");
  expect(classifyRustMangling("_RNvCs15kBYyAo9fc_7mycrate7example")).toBe("v0");
  const result = demangleRustSymbol("memcpy");
  expect(result).toEqual({
    demangled: null,
    mangled: "memcpy",
    format: "other",
    failure_reason: "Name does not use a Rust mangling scheme",
  });
});

it("returns structured failure reasons for malformed input", () => {
  const failures: readonly (readonly [string, RegExp])[] = [
    ["_ZN4demo", /terminating E/u],
    ["_RINvCs7qp2U7fqm6G_7mycrate7exampleAtj8_", /generic arguments/u],
    ["_RINtCs15kBYyAo9fc_7mycrate3fooB9_EB2_", /backref/u],
    ["_RNvNtNtCsgOH4LzxkuMq_7mycrateu7__ylb7e6escher4bach", /punycode/u],
    ["_ZN3fooE.llvm moocow", /suffix/u],
  ];
  for (const [mangled, reason] of failures) {
    const result = demangleRustSymbol(mangled);
    expect(result.demangled, mangled).toBeNull();
    expect(result.failure_reason ?? "", mangled).toMatch(reason);
  }
});

it("renders a large v0 binder list against the output budget instead of looping unbounded", () => {
  const started = performance.now();
  const result = demangleRustSymbol(
    "_RINvCs7qp2U7fqm6G_7mycrate7exampleFGZZZZZZZZ_EtEuEB2_",
  );
  const elapsedMs = performance.now() - started;
  expect(result.demangled).toBeNull();
  expect(result.failure_reason ?? "").toMatch(
    new RegExp(`${String(RUST_DEMANGLE_OUTPUT_CHARS)} character limit`, "u"),
  );
  expect(elapsedMs).toBeLessThan(200);
});

it("bounds the accepted mangled input length", () => {
  const result = demangleRustSymbol(
    `_RNvCs15kBYyAo9fc_7mycrate7example${"a".repeat(
      RUST_DEMANGLE_INPUT_BYTES,
    )}`,
  );
  expect(result.demangled).toBeNull();
  expect(result.failure_reason ?? "").toMatch(/byte limit/u);
});

it("bounds demangling work on recursive generic types", () => {
  let symbol = "_RINvCs7qp2U7fqm6G_7mycrate7example";
  for (let depth = 0; depth < 70; depth += 1) symbol += "S";
  symbol += "EB2_";
  const result = demangleRustSymbol(symbol);
  expect(result.demangled).toBeNull();
});
