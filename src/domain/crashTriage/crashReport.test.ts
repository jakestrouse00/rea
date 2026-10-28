import { describe, expect, it } from "vitest";

import {
  CRASH_REPORT_MAX_FRAME_CHARS,
  CRASH_REPORT_MAX_LABEL_CHARS,
  CrashReportParseFailure,
  parseCrashReport,
} from "./crashReport.js";

const ASAN_HEAP_OVERFLOW = `=================================================================
==1731==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x6020000000f1 at pc 0x000105a2b3c0 bp 0x00016f8d2a10 sp 0x00016f8d2a08
WRITE of size 4 at 0x6020000000f1 thread T0
    #0 0x105a2b3bb in parse_header /home/fuzz/src/parser.c:42:9
    #1 0x105a2b4cf in load_file /home/fuzz/src/loader.c:110:5
    #2 0x105a2b5ff in LLVMFuzzerTestOneInput /home/fuzz/src/fuzz.c:20:3
    #3 0x105bd0abc in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /opt/llvm/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:611:15
    #4 0x105c00123 in main /opt/llvm/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20:10
    #5 0x18f0a1234 in start+0x0 (/usr/lib/dyld:arm64e+0x1234)

Address 0x6020000000f1 is located 1 bytes to the right of 4-byte region [0x6020000000f0,0x6020000000f4)
allocated by thread T0 here:
    #0 0x105a1f000 in malloc (/opt/llvm/lib/clang/libclang_rt.asan_osx_dynamic.dylib:arm64e+0x12ab0)
    #1 0x105a2b100 in load_file /home/fuzz/src/loader.c:96:12

SUMMARY: AddressSanitizer: heap-buffer-overflow /home/fuzz/src/parser.c:42:9 in parse_header
Shadow bytes around the buggy address:
  0x0c0ff0000000: fa fa fd fd fa fa 00 00 fa fa 00 00 fa fa 00 00
==1731==ABORTING
`;

const TSAN_DATA_RACE = `==================
WARNING: ThreadSanitizer: data race (pid=4242)
  Write of size 8 at 0x000100a0b1c0 by thread T2:
    #0 0x100a0f123 in bump_counter /Users/fuzz/src/counter.c:14:3 (fuzz+0x100003f10)
    #1 0x100a0f2aa in worker_main /Users/fuzz/src/counter.c:31:7 (fuzz+0x100004020)

  Previous read of size 8 at 0x000100a0b1c0 by main thread:
    #0 0x100a0e990 in read_counter /Users/fuzz/src/counter.c:8:12 (fuzz+0x100003e00)

SUMMARY: ThreadSanitizer: data race /Users/fuzz/src/counter.c:14:3 in bump_counter
==================
ThreadSanitizer: reported 1 warnings
`;

const UBSAN_SIGNED_OVERFLOW = `fuzz.c:11:7: runtime error: signed integer overflow: 2147483647 + 1 cannot be represented in type 'int'
    #0 0x104c2a123 in compute_checksum /Users/fuzz/src/fuzz.c:11:7
    #1 0x104c2a240 in LLVMFuzzerTestOneInput /Users/fuzz/src/fuzz.c:27:3
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior fuzz.c:11:7 in
`;

const LSAN_LEAK = `=================================================================
==88==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 48 byte(s) in 1 object(s) allocated from:
    #0 0x1041a2f00 in malloc (/opt/llvm/lib/clang/libclang_rt.lsan_osx_dynamic.dylib:arm64e+0x12ab0)
    #1 0x1041b3100 in allocate_node /Users/fuzz/src/tree.c:64:12
    #2 0x1041b3a40 in main /Users/fuzz/src/tree.c:98:3

SUMMARY: LeakSanitizer: 48 byte(s) leaked in 1 allocation(s).
`;

const MSAN_UNINITIALIZED = `==31==WARNING: MemorySanitizer: use-of-uninitialized-value
    #0 0x1055a2c1f in read_length /Users/fuzz/src/wire.c:52:11
    #1 0x1055a3d02 in LLVMFuzzerTestOneInput /Users/fuzz/src/wire.c:88:5
    #2 0x1055a4120 in main /Users/fuzz/src/main.c:12:3

SUMMARY: MemorySanitizer: use-of-uninitialized-value /Users/fuzz/src/wire.c:52:11 in read_length
Exiting
`;

const MACOS_TEXT = `Incident Identifier: 9A1F0C6E-0000-4000-8000-000000000000
CrashReporter Key:   0000000000000000000000000000000000000000
Process:             fuzz [1731]
Path:                /Users/fuzz/build/fuzz
Identifier:          com.example.fuzz
Version:             1.0 (1)
Code Type:           ARM-64 (Native)
Role:                Foreground
OS Version:          macOS 15.1 (24B83)

Exception Type:  EXC_BAD_ACCESS (SIGSEGV)
Exception Codes: KERN_INVALID_ADDRESS at 0x0000000000000010
Termination Reason: SIGNAL 11 Segmentation fault: 11

Thread 0 Crashed:
0   libsystem_kernel.dylib        0x00000001891a0a5c __pthread_kill + 8
1   libsystem_pthread.dylib       0x00000001891d8f50 pthread_kill + 288
2   fuzz                          0x0000000104b2c1a0 parse_header + 64
3   fuzz                          0x0000000104b2d210 load_file + 132
4   fuzz                          0x0000000104b2e000 main + 128
5   dyld                          0x0000000188f0a000 start + 2360

Thread 1:
0   libsystem_kernel.dylib        0x00000001891a0f24 __psynch_cvwait + 8
1   fuzz                          0x0000000104b2f010 idle_loop + 12

Thread 1 crashed with ARM Thread State (64-bit):
    x0: 0x0000000000000000   x1: 0x0000000000000001

Binary Images:
       0x104b2c000 -        0x104b2ffff fuzz (0) <00000000-0000-0000-0000-000000000000> /Users/fuzz/build/fuzz
`;

const MACOS_IPS = `{"app_name":"fuzz","timestamp":"2026-10-24 10:00:00.00 -0400","app_version":"1.0","bug_type":"309"}
{
  "uptime" : 12000,
  "procLaunch" : "2026-10-24 09:58:00.00 -0400",
  "exception" : {"codes":"0x0000000000000001, 0x0000000000000010","rawCodes":[1,16],"type":"EXC_BAD_ACCESS","signal":"SIGSEGV","subtype":"KERN_INVALID_ADDRESS at 0x0000000000000010"},
  "termination" : {"flags":0,"code":11,"namespace":"SIGNAL","indicator":"Segmentation fault: 11","byProc":"exc handler","byPid":1731},
  "faultingThread" : 0,
  "threads" : [
    {"triggered":true,"id":1731,"frames":[
      {"imageOffset":1234,"symbol":"parse_header","symbolLocation":64,"imageIndex":1},
      {"imageOffset":2345,"symbol":"load_file","symbolLocation":132,"imageIndex":1},
      {"imageOffset":3456,"imageIndex":1}
    ],"threadState":{"flavor":"ARM_THREAD_STATE64"}}
  ],
  "usedImages" : [
    {"source":"P","arch":"arm64e","base":6488293376,"name":"dyld","path":"/usr/lib/dyld","uuid":"00000000-0000-0000-0000-000000000001"},
    {"source":"P","arch":"arm64","base":4373233664,"name":"fuzz","path":"/Users/fuzz/build/fuzz","uuid":"00000000-0000-0000-0000-000000000002"}
  ]
}
`;

describe("sanitizer report parsing", () => {
  it("keeps the crash stack and drops the allocation stack", () => {
    const facts = parseCrashReport(ASAN_HEAP_OVERFLOW);
    expect(facts.format).toBe("asan");
    expect(facts.sanitizer_class).toBe("address");
    expect(facts.crash_kind).toBe("heap-buffer-overflow");
    expect(facts.access).toBe("write");
    expect(facts.frames.map((frame) => frame.function)).toEqual([
      "parse_header",
      "load_file",
      "LLVMFuzzerTestOneInput",
      "fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long)",
      "main",
      "start",
    ]);
    expect(facts.frames[0]).toMatchObject({
      index: 0,
      source_file: "/home/fuzz/src/parser.c",
      source_line: 42,
    });
    expect(facts.frames[5]).toMatchObject({
      function: "start",
      module: "dyld",
      offset: 0x1234,
    });
    expect(facts.summary).toBe(
      "SUMMARY: AddressSanitizer: heap-buffer-overflow /home/fuzz/src/parser.c:42:9 in parse_header",
    );
  });

  it("reads a ThreadSanitizer report and keeps only the reported access stack", () => {
    const facts = parseCrashReport(TSAN_DATA_RACE);
    expect(facts.format).toBe("tsan");
    expect(facts.sanitizer_class).toBe("thread");
    expect(facts.crash_kind).toBe("data-race");
    expect(facts.access).toBe("write");
    expect(facts.frames.map((frame) => frame.function)).toEqual([
      "bump_counter",
      "worker_main",
    ]);
    expect(facts.frames[0]?.module).toBe("fuzz");
  });

  it("reads an UndefinedBehaviorSanitizer runtime error", () => {
    const facts = parseCrashReport(UBSAN_SIGNED_OVERFLOW);
    expect(facts.format).toBe("ubsan");
    expect(facts.sanitizer_class).toBe("undefined");
    expect(facts.crash_kind).toBe("signed-integer-overflow");
    expect(facts.frames.map((frame) => frame.function)).toEqual([
      "compute_checksum",
      "LLVMFuzzerTestOneInput",
    ]);
  });

  it("reads LeakSanitizer and MemorySanitizer reports", () => {
    const leak = parseCrashReport(LSAN_LEAK);
    expect(leak.format).toBe("lsan");
    expect(leak.sanitizer_class).toBe("leak");
    expect(leak.crash_kind).toBe("detected-memory-leaks");
    expect(leak.frames).toHaveLength(3);

    const memory = parseCrashReport(MSAN_UNINITIALIZED);
    expect(memory.format).toBe("msan");
    expect(memory.sanitizer_class).toBe("memory");
    expect(memory.crash_kind).toBe("use-of-uninitialized-value");
    expect(memory.frames[0]?.source_line).toBe(52);
  });
});

describe("macOS crash report parsing", () => {
  it("selects the crashed thread and separates symbols from offsets", () => {
    const facts = parseCrashReport(MACOS_TEXT);
    expect(facts.format).toBe("macos-text");
    expect(facts.sanitizer_class).toBe("none");
    expect(facts.crash_kind).toBe("exc-bad-access");
    expect(facts.signal).toBe("SIGSEGV");
    expect(facts.exception_type).toBe("EXC_BAD_ACCESS");
    expect(facts.termination_reason).toBe("SIGNAL 11 Segmentation fault: 11");
    expect(facts.frames.map((frame) => frame.function)).toEqual([
      "__pthread_kill",
      "pthread_kill",
      "parse_header",
      "load_file",
      "main",
      "start",
    ]);
    expect(facts.frames[0]).toMatchObject({
      module: "libsystem_kernel.dylib",
      offset: 8,
    });
  });

  it("reads a two-part .ips report and its faulting thread", () => {
    const facts = parseCrashReport(MACOS_IPS);
    expect(facts.format).toBe("macos-ips");
    expect(facts.crash_kind).toBe("exc-bad-access");
    expect(facts.signal).toBe("SIGSEGV");
    expect(facts.frames.map((frame) => frame.function)).toEqual([
      "parse_header",
      "load_file",
      null,
    ]);
    expect(facts.frames[2]).toMatchObject({ module: "fuzz", offset: 3456 });
  });

  it("accepts a single-object .ips body", () => {
    const body = MACOS_IPS.slice(MACOS_IPS.indexOf("\n") + 1).trim();
    const object = { ...JSON.parse(body), bug_type: "309" } as unknown;
    const facts = parseCrashReport(JSON.stringify(object));
    expect(facts.format).toBe("macos-ips");
    expect(facts.frames).toHaveLength(3);
  });
});

describe("report text budget", () => {
  it("clips an oversized frame symbol and says so", () => {
    const symbol = "a".repeat(400_000);
    const facts = parseCrashReport(
      [
        "==9==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x0",
        `    #0 0x1000 in ${symbol} /src/parser.c:42:9`,
        "    #1 0x2000 in main /src/main.c:9:1",
        "SUMMARY: AddressSanitizer: heap-buffer-overflow",
      ].join("\n"),
    );
    expect(facts.frames[0]?.function).toHaveLength(
      CRASH_REPORT_MAX_FRAME_CHARS,
    );
    expect(facts.frames[0]?.function?.endsWith("…")).toBe(true);
    expect(facts.frames[0]?.text_truncated).toBe(true);
    expect(facts.frames[1]?.text_truncated).toBe(false);
    expect(facts.text_truncated).toBe(true);
  });

  it("clips an oversized macOS exception label", () => {
    const label = "A".repeat(100_000);
    const facts = parseCrashReport(
      [
        `Exception Type:  ${label} (SIGSEGV)`,
        "Thread 0 Crashed:",
        "0   fuzz   0x0000000104b2c1a0 parse_header + 64",
        "",
      ].join("\n"),
    );
    expect(facts.exception_type).toHaveLength(CRASH_REPORT_MAX_LABEL_CHARS);
    expect(facts.exception_type?.endsWith("…")).toBe(true);
    expect(facts.text_truncated).toBe(true);
    expect(facts.crash_kind.length).toBeLessThanOrEqual(64);
  });

  it("leaves ordinary reports unflagged", () => {
    const facts = parseCrashReport(ASAN_HEAP_OVERFLOW);
    expect(facts.text_truncated).toBe(false);
    expect(facts.frames.every((frame) => !frame.text_truncated)).toBe(true);
  });
});

describe("UndefinedBehaviorSanitizer summary-only reports", () => {
  it("keeps the location out of the crash kind", () => {
    const facts = parseCrashReport(
      [
        "SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior fuzz.c:11:7 in",
        "    #0 0x104c2a123 in compute_checksum /Users/fuzz/src/fuzz.c:11:7",
        "SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior fuzz.c:11:7 in",
      ].join("\n"),
    );
    expect(facts.format).toBe("ubsan");
    expect(facts.crash_kind).toBe("undefined-behavior");
    expect(facts.crash_kind).not.toMatch(/fuzz|src/u);
  });
});

describe("malformed report boundaries", () => {
  it("refuses empty and unrecognized bodies", () => {
    expect(() => parseCrashReport("   \n")).toThrowError(
      CrashReportParseFailure,
    );
    expect(() => parseCrashReport("hello world\n")).toThrowError(
      /not a recognized/u,
    );
    try {
      parseCrashReport("");
    } catch (cause: unknown) {
      expect(cause).toBeInstanceOf(CrashReportParseFailure);
      expect((cause as CrashReportParseFailure).reason).toBe("empty");
    }
  });

  it("refuses a sanitizer banner with no frames", () => {
    try {
      parseCrashReport(
        "==1==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000\n==1==ABORTING\n",
      );
      expect.unreachable();
    } catch (cause: unknown) {
      expect(cause).toBeInstanceOf(CrashReportParseFailure);
      expect((cause as CrashReportParseFailure).reason).toBe("no_frames");
    }
  });

  it("refuses an .ips body that is not JSON", () => {
    expect(() =>
      parseCrashReport('{"bug_type":"309"}\n{"threads": [oops'),
    ).toThrowError(CrashReportParseFailure);
  });

  it("refuses a macOS report that names no thread stack", () => {
    try {
      parseCrashReport(
        "Exception Type:  EXC_CRASH (SIGABRT)\nTermination Reason: SIGNAL 6\n",
      );
      expect.unreachable();
    } catch (cause: unknown) {
      expect(cause).toBeInstanceOf(CrashReportParseFailure);
      expect((cause as CrashReportParseFailure).reason).toBe("no_frames");
    }
  });

  it("bounds every retained summary line", () => {
    const long = `SUMMARY: AddressSanitizer: heap-buffer-overflow ${"a".repeat(500)}`;
    const facts = parseCrashReport(
      [
        "==7==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x0",
        "    #0 0x1000 in parse /src/a.c:1:1",
        long,
      ].join("\n"),
    );
    expect(facts.summary).not.toBeNull();
    expect((facts.summary ?? "").length).toBeLessThanOrEqual(200);
    expect(facts.summary).toContain("…");
  });
});
