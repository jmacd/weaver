// SPDX-License-Identifier: Apache-2.0

//! WebAssembly module for OpenTelemetry Weaver semantic convention validation.
//!
//! This crate compiles to a `.wasm` module that can be loaded in-process by a
//! Go (or other) host via a WASM runtime such as wazero. It exposes the Rego
//! policy engine from `weaver_checker` through a C-ABI interface.
//!
//! # Exported functions
//!
//! * `alloc(len) -> ptr` — allocate `len` bytes in the WASM module's memory.
//! * `dealloc(ptr, len)` — free a previous allocation.
//! * `init(policies_ptr, policies_len) -> status` — load Rego policies.
//! * `check(input_ptr, input_len, result_ptr_out, result_len_out) -> status` — evaluate policies.
//! * `free_result(ptr, len)` — free a result buffer returned by `check`.

use std::cell::RefCell;
use std::slice;

use weaver_checker::{Engine, PolicyStage};
use weaver_resolved_schema::registry::Registry;

// Global state (single-threaded WASM).
thread_local! {
    static ENGINE: RefCell<Option<Engine>> = const { RefCell::new(None) };
    static REGISTRY: RefCell<Option<Registry>> = const { RefCell::new(None) };
}

/// A policy entry as received from the host via JSON.
#[derive(serde::Deserialize)]
struct PolicyEntry {
    /// Filename used for error reporting.
    filename: String,
    /// The Rego policy source code.
    content: String,
}

// ---------------------------------------------------------------------------
// Memory management exports
// ---------------------------------------------------------------------------

/// Allocate `len` bytes in the WASM linear memory and return a pointer.
/// The host writes data into this region before calling `init` or `check`.
#[no_mangle]
pub extern "C" fn alloc(len: u32) -> *mut u8 {
    let layout = std::alloc::Layout::from_size_align(len as usize, 1).expect("invalid layout");
    // SAFETY: layout has non-zero size (enforced by caller contract).
    unsafe { std::alloc::alloc(layout) }
}

/// Free a region previously allocated by `alloc`.
#[no_mangle]
pub extern "C" fn dealloc(ptr: *mut u8, len: u32) {
    if ptr.is_null() || len == 0 {
        return;
    }
    let layout = std::alloc::Layout::from_size_align(len as usize, 1).expect("invalid layout");
    // SAFETY: ptr was allocated by `alloc` with the same layout.
    unsafe { std::alloc::dealloc(ptr, layout) };
}

// ---------------------------------------------------------------------------
// Engine lifecycle
// ---------------------------------------------------------------------------

/// Initialize the policy engine with Rego policies.
///
/// `policies_ptr` / `policies_len` point to a UTF-8 JSON array of objects,
/// each with `filename` and `content` fields:
///
/// ```json
/// [
///   {"filename": "semconv.rego", "content": "package ..."},
///   {"filename": "custom.rego",  "content": "package ..."}
/// ]
/// ```
///
/// Returns 0 on success, 1 on JSON parse error, 2 on policy load error.
#[no_mangle]
pub extern "C" fn init(policies_ptr: *const u8, policies_len: u32) -> i32 {
    let policies_bytes =
        unsafe { slice::from_raw_parts(policies_ptr, policies_len as usize) };

    let policies: Vec<PolicyEntry> = match serde_json::from_slice(policies_bytes) {
        Ok(p) => p,
        Err(_) => return 1,
    };

    let mut engine = Engine::new();

    for entry in &policies {
        if engine.add_policy(&entry.filename, &entry.content).is_err() {
            return 2;
        }
    }

    ENGINE.with(|e| {
        *e.borrow_mut() = Some(engine);
    });

    0
}

/// Set the data document (registry / static knowledge) for the policy engine.
///
/// `data_ptr` / `data_len` point to a UTF-8 JSON object that will be merged
/// into the engine's data namespace.
///
/// Returns 0 on success, 1 on JSON parse error, 2 on engine error,
/// 3 if engine not initialized.
#[no_mangle]
pub extern "C" fn set_data(data_ptr: *const u8, data_len: u32) -> i32 {
    let data_bytes = unsafe { slice::from_raw_parts(data_ptr, data_len as usize) };

    let data: serde_json::Value = match serde_json::from_slice(data_bytes) {
        Ok(d) => d,
        Err(_) => return 1,
    };

    ENGINE.with(|e| {
        let mut engine_ref = e.borrow_mut();
        let engine = match engine_ref.as_mut() {
            Some(eng) => eng,
            None => return 3,
        };
        match engine.add_data(&data) {
            Ok(()) => 0,
            Err(_) => 2,
        }
    })
}

/// Load a resolved semantic convention registry.
///
/// `registry_ptr` / `registry_len` point to a UTF-8 JSON representation of a
/// resolved `Registry` (as produced by `weaver registry resolve`).
///
/// Returns 0 on success, 1 on JSON parse error.
#[no_mangle]
pub extern "C" fn set_registry(registry_ptr: *const u8, registry_len: u32) -> i32 {
    let registry_bytes = unsafe { slice::from_raw_parts(registry_ptr, registry_len as usize) };

    let registry: Registry = match serde_json::from_slice(registry_bytes) {
        Ok(r) => r,
        Err(_) => return 1,
    };

    REGISTRY.with(|r| {
        *r.borrow_mut() = Some(registry);
    });

    0
}

/// Evaluate the loaded policies against an input document.
///
/// `input_ptr` / `input_len` point to a UTF-8 JSON object used as `input`
/// in the Rego evaluation.
///
/// `stage` selects the policy stage:
///   0 = `before_resolution`
///   1 = `after_resolution`
///   2 = `comparison_after_resolution`
///   3 = `live_check_advice`
///
/// On success, writes the result JSON pointer and length into `result_ptr_out`
/// and `result_len_out`. The caller must free the result with `free_result`.
///
/// Returns 0 on success, 1 on JSON parse error, 2 on evaluation error,
/// 3 if engine not initialized, 4 on invalid stage.
#[no_mangle]
pub extern "C" fn check(
    input_ptr: *const u8,
    input_len: u32,
    stage: i32,
    result_ptr_out: *mut *const u8,
    result_len_out: *mut u32,
) -> i32 {
    let input_bytes = unsafe { slice::from_raw_parts(input_ptr, input_len as usize) };

    let input: serde_json::Value = match serde_json::from_slice(input_bytes) {
        Ok(v) => v,
        Err(_) => return 1,
    };

    let policy_stage = match stage {
        0 => PolicyStage::BeforeResolution,
        1 => PolicyStage::AfterResolution,
        2 => PolicyStage::ComparisonAfterResolution,
        3 => PolicyStage::LiveCheckAdvice,
        _ => return 4,
    };

    ENGINE.with(|e| {
        let mut engine_ref = e.borrow_mut();
        let engine = match engine_ref.as_mut() {
            Some(eng) => eng,
            None => return 3,
        };

        if engine.set_input(&input).is_err() {
            return 1;
        }

        let findings = match engine.check(policy_stage) {
            Ok(f) => f,
            Err(_) => return 2,
        };

        let result_json = match serde_json::to_vec(&findings) {
            Ok(j) => j,
            Err(_) => return 2,
        };

        let len = result_json.len();
        let ptr = result_json.as_ptr();
        std::mem::forget(result_json);

        unsafe {
            *result_ptr_out = ptr;
            *result_len_out = len as u32;
        }

        0
    })
}

/// Free a result buffer previously returned by `check`.
#[no_mangle]
pub extern "C" fn free_result(ptr: *const u8, len: u32) {
    if ptr.is_null() || len == 0 {
        return;
    }
    // Reconstruct the Vec and drop it.
    unsafe {
        let _ = Vec::from_raw_parts(ptr as *mut u8, len as usize, len as usize);
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_and_check() {
        let policies = serde_json::json!([
            {
                "filename": "test.rego",
                "content": r#"
                    package live_check_advice

                    import rego.v1

                    deny contains result if {
                        input.name == "bad"
                        result := {
                            "id": "test_violation",
                            "level": "violation",
                            "message": "Name cannot be 'bad'"
                        }
                    }
                "#
            }
        ]);

        let policies_bytes = serde_json::to_vec(&policies).unwrap();
        let status = init(policies_bytes.as_ptr(), policies_bytes.len() as u32);
        assert_eq!(status, 0, "init should succeed");

        // Check with violating input
        let input = serde_json::json!({"name": "bad"});
        let input_bytes = serde_json::to_vec(&input).unwrap();
        let mut result_ptr: *const u8 = std::ptr::null();
        let mut result_len: u32 = 0;

        let status = check(
            input_bytes.as_ptr(),
            input_bytes.len() as u32,
            3, // LiveCheckAdvice stage
            &mut result_ptr,
            &mut result_len,
        );
        assert_eq!(status, 0, "check should succeed");

        let result_bytes = unsafe { slice::from_raw_parts(result_ptr, result_len as usize) };
        let result_str = std::str::from_utf8(result_bytes).expect("valid UTF-8");
        let findings: Vec<serde_json::Value> =
            serde_json::from_str(result_str).expect("valid JSON");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0]["id"], "test_violation");
        assert_eq!(findings[0]["level"], "violation");

        free_result(result_ptr, result_len);

        // Check with non-violating input
        let input = serde_json::json!({"name": "good"});
        let input_bytes = serde_json::to_vec(&input).unwrap();
        let mut result_ptr: *const u8 = std::ptr::null();
        let mut result_len: u32 = 0;

        let status = check(
            input_bytes.as_ptr(),
            input_bytes.len() as u32,
            3,
            &mut result_ptr,
            &mut result_len,
        );
        assert_eq!(status, 0);

        let result_bytes = unsafe { slice::from_raw_parts(result_ptr, result_len as usize) };
        let findings: Vec<serde_json::Value> =
            serde_json::from_slice(result_bytes).unwrap();
        assert!(findings.is_empty(), "no violations expected");

        free_result(result_ptr, result_len);
    }
}
