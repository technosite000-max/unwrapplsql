// UnwrapPLSQL - Premium PL/SQL Unwrapper & Analyzer
// Uses public domain substitution table and Pako for zlib decompression
// Fallback heuristics for edge cases

// ============================================================
// ORACLE 10G+ SUBSTITUTION TABLE (Public Domain)
// Source: Niels Teusink's unwrap.py research
// ============================================================
const SUBSTITUTION_TABLE = new Uint8Array([
    0x3d, 0x65, 0x85, 0xb3, 0x18, 0xdb, 0xe2, 0x87, 0xf1, 0x52, 0xab, 0x63,
    0x4b, 0xb5, 0xa0, 0x5f, 0x7c, 0xca, 0x6f, 0x9b, 0xd6, 0xfe, 0x26, 0x34,
    0x0c, 0x7e, 0x3e, 0x68, 0x14, 0xb6, 0xbd, 0x43, 0xd2, 0x32, 0x1a, 0x95,
    0x99, 0x8b, 0x9d, 0x77, 0x4f, 0x29, 0x07, 0x8e, 0xea, 0x1c, 0x90, 0xba,
    0x01, 0xf5, 0x2b, 0xf2, 0x2e, 0x8d, 0x9e, 0x1b, 0x56, 0x9f, 0xe8, 0xf7,
    0xcd, 0x5d, 0x49, 0x05, 0xc2, 0xc6, 0xeb, 0x39, 0x47, 0xda, 0x8a, 0xd3,
    0x5b, 0x3c, 0x7b, 0xb0, 0x59, 0x16, 0x78, 0x3f, 0x35, 0xbb, 0x20, 0x4e,
    0xa8, 0x38, 0x71, 0x19, 0x33, 0x11, 0x6e, 0x9c, 0xaf, 0x55, 0x10, 0x6a,
    0xa3, 0xa1, 0x88, 0x42, 0x09, 0x89, 0x5c, 0xde, 0xb8, 0x76, 0xcb, 0xbc,
    0x1f, 0xbf, 0x44, 0xd7, 0x3b, 0xfc, 0x2a, 0xac, 0xa7, 0x40, 0x15, 0x24,
    0x28, 0x51, 0x7a, 0x02, 0x69, 0xa9, 0xc8, 0xaa, 0x8c, 0xfa, 0x86, 0x0f,
    0x82, 0xe0, 0x22, 0xd1, 0x6d, 0x2d, 0x94, 0xd5, 0xc9, 0x1d, 0x00, 0x66,
    0x92, 0xe6, 0x9a, 0x6c, 0x03, 0xb9, 0x4c, 0x80, 0x6b, 0xef, 0x06, 0x67,
    0x13, 0x0b, 0xad, 0x5a, 0xc4, 0xbe, 0x0e, 0x97, 0x75, 0x45, 0x3a, 0xdf,
    0x2f, 0x21, 0x41, 0x04, 0x12, 0x83, 0x91, 0x23, 0x4d, 0x70, 0x2c, 0x30,
    0xf4, 0x0a, 0x54, 0x7f, 0xa2, 0x27, 0x8f, 0xee, 0x95, 0xf8, 0xed, 0x5e,
    0xd8, 0xb7, 0xfb, 0xe5, 0xce, 0xa6, 0x31, 0x79, 0xb2, 0x0d, 0x1e, 0xec,
    0x25, 0x08, 0xae, 0xb1, 0xc3, 0x7d, 0x50, 0x4a, 0x57, 0x46, 0x64, 0x73,
    0xf3, 0x36, 0x81, 0x48, 0xe9, 0x84, 0xc1, 0xe3, 0xa5, 0xcc, 0xa4, 0xe7,
    0xd0, 0xc5, 0xcf, 0x58, 0x17, 0xff, 0x96, 0xf0, 0xdd, 0xd4, 0xfd, 0xe4,
    0xc7, 0xf9, 0x60, 0x98, 0x61, 0x72, 0x53, 0x74, 0xdc, 0xf6, 0xc0, 0xb4,
    0x93, 0xe1, 0x62, 0xd9
]);

// Build reverse table for decoding
function buildReverseTable() {
    const rev = new Uint8Array(256);
    for (let i = 0; i < 256; i++) {
        rev[SUBSTITUTION_TABLE[i]] = i;
    }
    return rev;
}
const REVERSE_TABLE = buildReverseTable();

// ============================================================
// CORE UNWRAPPING FUNCTION (Oracle 10g+)
// Requires Pako library (included via script tag in HTML)
// ============================================================
function unwrapOracle10gPlus(wrappedText) {
    // Step 1: Extract Base64 body from wrapped text
    const lines = wrappedText.split('\n');
    let b64String = '';
    let inBody = false;
    
    for (const line of lines) {
        const trimmed = line.trim();
        if (!inBody) {
            // Skip header lines (typically contain CREATE, wrapped, hex numbers)
            if (trimmed && !trimmed.match(/^(CREATE|wrapped|\s*[0-9a-f]{2,}\s*[0-9a-f]{2,})/i) && 
                !trimmed.startsWith('/') && !trimmed.startsWith('END')) {
                inBody = true;
            } else {
                continue;
            }
        }
        if (inBody && trimmed && !trimmed.startsWith('/') && !trimmed.toLowerCase().startsWith('end')) {
            b64String += trimmed;
        }
    }
    
    if (!b64String) {
        throw new Error('No Base64 body found in wrapped code');
    }
    
    // Step 2: Base64 decode
    let rawBytes;
    try {
        const binaryString = atob(b64String);
        rawBytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            rawBytes[i] = binaryString.charCodeAt(i);
        }
    } catch (e) {
        throw new Error('Invalid Base64 content: ' + e.message);
    }
    
    // Step 3: Reverse substitution using table
    for (let i = 0; i < rawBytes.length; i++) {
        rawBytes[i] = REVERSE_TABLE[rawBytes[i]];
    }
    
    // Step 4: Skip SHA-1 hash (first 20 bytes)
    if (rawBytes.length <= 20) {
        throw new Error('Data too short to contain compressed content');
    }
    const compressedData = rawBytes.slice(20);
    
    // Step 5: LZ decompression using Pako (zlib)
    try {
        // Pako's inflate returns Uint8Array; convert to string
        const decompressed = pako.inflate(compressedData, { to: 'string' });
        return decompressed;
    } catch (e) {
        throw new Error('Decompression failed: ' + e.message);
    }
}

// ============================================================
// FALLBACK HEURISTIC ANALYZERS (for 9i, non-standard, or failures)
// ============================================================
function detectWrapped(input) {
    const lowerInput = input.toLowerCase();
    
    if (lowerInput.includes("wrapped") || 
        (lowerInput.includes("wrap") && lowerInput.includes("create")) ||
        input.match(/^[A-Za-z0-9+/=\s]{100,}$/)) {
        
        let version = "Standard Wrap";
        if (input.includes("9i") || input.match(/^[0-9A-Fa-f]{100,}$/)) {
            version = "Oracle 9i Wrap";
        } else if (input.match(/^[A-Za-z0-9+/=]{200,}$/)) {
            version = "Oracle 10g+ Wrap";
        }
        return { isWrapped: true, version };
    }
    return { isWrapped: false, version: null };
}

function cleanBase64(str) {
    let cleaned = str.replace(/[^A-Za-z0-9+/=]/g, "");
    while (cleaned.length % 4) cleaned += "=";
    return cleaned;
}

function extractOracleWrapPatterns(input) {
    const lines = input.split('\n');
    const readable = [];
    
    for (let line of lines) {
        const stringMatches = line.match(/'[^']*'/g);
        if (stringMatches) {
            readable.push(...stringMatches.map(s => s.slice(1, -1)));
        }
        const keywords = ['PROCEDURE', 'FUNCTION', 'PACKAGE', 'BEGIN', 'END', 
                          'EXCEPTION', 'IF', 'THEN', 'ELSE', 'LOOP', 'FOR', 
                          'WHILE', 'RETURN', 'DECLARE', 'CURSOR', 'SELECT', 
                          'INSERT', 'UPDATE', 'DELETE', 'FROM', 'WHERE'];
        const upperLine = line.toUpperCase();
        keywords.forEach(kw => {
            if (upperLine.includes(kw)) {
                readable.push(kw);
            }
        });
    }
    return readable.length > 0 ? readable.join('\n') : null;
}

function hexDecode(str) {
    const hexMatch = str.match(/[0-9A-Fa-f]{2,}/g);
    if (!hexMatch) return null;
    
    const hexString = hexMatch.join('');
    if (hexString.length % 2 !== 0) return null;
    
    let result = "";
    for (let i = 0; i < hexString.length; i += 2) {
        const charCode = parseInt(hexString.substr(i, 2), 16);
        if (charCode >= 32 && charCode <= 126) {
            result += String.fromCharCode(charCode);
        }
    }
    return result;
}

function extractReadableStrings(input) {
    const matches = input.match(/[ -~]{5,}/g);
    if (!matches) return null;
    const filtered = matches.filter(m => !m.match(/^[A-Za-z0-9+/=]+$/));
    return filtered.length > 0 ? filtered.join('\n') : null;
}

function isReadable(str) {
    const readable = str.replace(/[^\x20-\x7E\n\r\t]/g, "").length;
    return readable / str.length > 0.7;
}

function formatOutput(content, method) {
    return `/* ===== UnwrapPLSQL Full Unwrap ===== */
/* Method: ${method} */
/* Timestamp: ${new Date().toLocaleString()} */
/* ======================================== */

${content}

/* ===== End of Unwrapped Source ===== */`;
}

// ============================================================
// UI & MAIN ANALYSIS FLOW
// ============================================================
let isDark = true;

function toggleTheme() {
    document.body.classList.toggle('light');
    isDark = !isDark;
    document.getElementById('themeToggle').innerHTML = isDark ? '🌙 Dark' : '☀️ Light';
}

function analyze() {
    const input = document.getElementById("input").value.trim();
    const outputEl = document.getElementById("output");
    
    if (!input) {
        setOutput("⚠ Please paste wrapped PL/SQL code to analyze.");
        resetStats();
        return;
    }

    outputEl.value = "🔍 Analyzing and attempting full unwrap...";
    outputEl.classList.add('analyzing');
    
    // Use setTimeout to allow UI update before heavy computation
    setTimeout(() => {
        performAnalysis(input);
        outputEl.classList.remove('analyzing');
    }, 50);
}

function performAnalysis(input) {
    resetStats();
    
    // Detect wrap status
    const wrapDetection = detectWrapped(input);
    if (!wrapDetection.isWrapped) {
        setOutput(`❌ Not a wrapped PL/SQL block\n\nThis doesn't appear to be Oracle wrapped PL/SQL code.\n\nLook for:\n• CREATE OR REPLACE ... wrapped\n• Base64-like encoded strings\n• The word "wrapped" in the header`);
        document.getElementById("detect").innerText = "Not Wrapped";
        document.getElementById("confidence").innerText = "N/A";
        return;
    }
    
    document.getElementById("detect").innerText = "✓ Wrapped";
    document.getElementById("wrapType").innerText = wrapDetection.version || "Unknown";
    
    let result = "";
    let strategy = "";
    let confidence = "";
    
    // ===== PRIMARY: Full Oracle 10g+ Unwrap =====
    try {
        const unwrapped = unwrapOracle10gPlus(input);
        if (unwrapped && unwrapped.trim().length > 10) {
            result = formatOutput(unwrapped, "Full Oracle 10g+ Unwrap Algorithm");
            strategy = "Full Unwrap (10g+)";
            confidence = "High";
        }
    } catch (e) {
        console.log("Full unwrap failed, falling back to heuristic analyzers:", e.message);
        // Continue to fallbacks
    }
    
    // ===== FALLBACK: Heuristic Methods =====
    if (!result) {
        // Try Base64 decode (for partial fragments)
        try {
            const cleaned = cleanBase64(input);
            const decoded = atob(cleaned);
            if (isReadable(decoded) && decoded.length > 10) {
                result = formatOutput(decoded, "Base64 Fragment Extraction");
                strategy = "Base64 Decode (Fragment)";
                confidence = "Medium";
            }
        } catch (e) {}
    }
    
    if (!result) {
        const extracted = extractOracleWrapPatterns(input);
        if (extracted && extracted.length > 5) {
            result = formatOutput(extracted, "Pattern Extraction");
            strategy = "Pattern Extraction";
            confidence = "Low";
        }
    }
    
    if (!result) {
        const hexDecoded = hexDecode(input);
        if (hexDecoded && isReadable(hexDecoded) && hexDecoded.length > 10) {
            result = formatOutput(hexDecoded, "Hex Decode");
            strategy = "Hex Decode";
            confidence = "Low";
        }
    }
    
    if (!result) {
        const strings = extractReadableStrings(input);
        if (strings && strings.length > 5) {
            result = formatOutput(strings, "String Extraction");
            strategy = "String Extraction";
            confidence = "Very Low";
        }
    }
    
    // ===== FINAL OUTPUT =====
    if (result) {
        setOutput(result);
        document.getElementById("strategy").innerText = strategy;
        document.getElementById("confidence").innerText = confidence;
    } else {
        setOutput(`⚠ Unable to extract meaningful content.\n\nOracle wrap is one-way obfuscation. This code may be from Oracle 9i (different algorithm) or corrupted.\n\nWhat we detected:\n• Wrap type: ${wrapDetection.version || 'Standard'}\n• This tool fully supports Oracle 10g and later wraps.\n\nFor 9i wraps, the recovery is limited to pattern extraction.`);
        document.getElementById("strategy").innerText = "None successful";
        document.getElementById("confidence").innerText = "Very Low";
    }
}

function setOutput(text) {
    document.getElementById("output").value = text;
}

function resetStats() {
    document.getElementById("detect").innerText = "—";
    document.getElementById("wrapType").innerText = "—";
    document.getElementById("strategy").innerText = "—";
    document.getElementById("confidence").innerText = "—";
}

function clearAll() {
    document.getElementById("input").value = "";
    document.getElementById("output").value = "";
    resetStats();
}

function copyOutput() {
    const output = document.getElementById("output");
    output.select();
    document.execCommand("copy");
    
    const btn = document.getElementById("copyBtn");
    const originalHtml = btn.innerHTML;
    btn.innerHTML = '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path></svg> Copied!';
    setTimeout(() => {
        btn.innerHTML = originalHtml;
    }, 2000);
}

function pasteExample() {
    const example = `CREATE OR REPLACE PROCEDURE hello_world wrapped 
a000000
369
abcd
abcd
abcd
abcd
abcd
abcd
abcd
abcd
abcd
abcd
abcd
abcd
abcd
abcd
abcd
7
4e 8e
gH3k3xYD5Q3h0S6hZgJW8B+9Vv8wgxDJ2fIGyC9NCL8YG4vIR5RnP0ZpN5VJv1L0X2kM
3nO8pQrS5tU7vW9xY0zA2bC4dE6fG8hI0jK1lM2nO3pQ4rS5tU6vW7xY8zA9bC0dE1fG2h
I3jK4lM5nO6pQ7rS8tU9vW0xY1zA2bC3dE4fG5hI6jK7lM8nO9pQ0rS1tU2vW3xY4zA5bC6
/`;
    document.getElementById("input").value = example;
    analyze();
}

// Initialize theme
document.addEventListener('DOMContentLoaded', () => {
    isDark = true;
});
