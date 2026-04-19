// UnwrapPLSQL - Core Analysis Engine
// Premium Decoding Strategies

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

  // Show analyzing state
  outputEl.value = "🔍 Analyzing code...";
  outputEl.classList.add('analyzing');
  
  setTimeout(() => {
    performAnalysis(input);
    outputEl.classList.remove('analyzing');
  }, 100);
}

function performAnalysis(input) {
  // Reset stats
  document.getElementById("detect").innerText = "—";
  document.getElementById("wrapType").innerText = "—";
  document.getElementById("strategy").innerText = "—";
  document.getElementById("confidence").innerText = "—";

  // Check if wrapped
  const isWrapped = detectWrapped(input);
  
  if (!isWrapped.isWrapped) {
    setOutput(`❌ Not a wrapped PL/SQL block\n\nThis doesn't appear to be Oracle wrapped PL/SQL code.\n\nLook for:\n• CREATE OR REPLACE ... wrapped\n• Base64-like encoded strings\n• The word "wrapped" in the header`);
    document.getElementById("detect").innerText = "Not Wrapped";
    document.getElementById("confidence").innerText = "N/A";
    return;
  }

  document.getElementById("detect").innerText = "✓ Wrapped";
  document.getElementById("wrapType").innerText = isWrapped.version || "Unknown";

  // Try multiple decoding strategies
  let result = "";
  let strategy = "";
  let confidence = "";

  // Strategy 1: Clean Base64 decode (most common for newer Oracle versions)
  try {
    const cleaned = cleanBase64(input);
    const decoded = atob(cleaned);
    if (isReadable(decoded) && decoded.length > 10) {
      result = formatOutput(decoded, "Base64 Decode");
      strategy = "Base64 Decode";
      confidence = "High";
    }
  } catch (e) {
    // Continue to next strategy
  }

  // Strategy 2: Oracle wrap specific pattern extraction
  if (!result) {
    try {
      const extracted = extractOracleWrapPatterns(input);
      if (extracted && extracted.length > 10) {
        result = formatOutput(extracted, "Pattern Extraction");
        strategy = "Pattern Extraction";
        confidence = "Medium";
      }
    } catch (e) {}
  }

  // Strategy 3: Hex decode attempt (older Oracle versions)
  if (!result) {
    try {
      const hexDecoded = hexDecode(input);
      if (isReadable(hexDecoded) && hexDecoded.length > 10) {
        result = formatOutput(hexDecoded, "Hex Decode");
        strategy = "Hex Decode";
        confidence = "Low";
      }
    } catch (e) {}
  }

  // Strategy 4: String extraction (last resort)
  if (!result) {
    const extracted = extractReadableStrings(input);
    if (extracted && extracted.length > 5) {
      result = formatOutput(extracted, "String Extraction");
      strategy = "String Extraction";
      confidence = "Low";
    }
  }

  // Update UI
  if (result) {
    setOutput(result);
    document.getElementById("strategy").innerText = strategy;
    document.getElementById("confidence").innerText = confidence;
  } else {
    setOutput(`⚠ Unable to extract meaningful content from this wrapped code.\n\nOracle's wrap utility is designed to be irreversible. The code is obfuscated, not encrypted.\n\nWhat we detected:\n• Wrap type: ${isWrapped.version || 'Standard Oracle Wrap'}\n• This is a one-way protection mechanism\n\nFor recovery options, check our PL/SQL Guide.`);
    document.getElementById("strategy").innerText = "None successful";
    document.getElementById("confidence").innerText = "Very Low";
  }
}

function detectWrapped(input) {
  const lowerInput = input.toLowerCase();
  
  // Check for wrap indicators
  if (lowerInput.includes("wrapped") || 
      lowerInput.includes("wrap") && lowerInput.includes("create") ||
      lowerInput.match(/^[A-Za-z0-9+/=\s]{100,}$/)) {
    
    // Detect version
    let version = "Standard Wrap";
    if (input.includes("9i") || input.match(/^[0-9A-Fa-f]{100,}$/)) {
      version = "Oracle 9i Wrap";
    } else if (input.match(/^[A-Za-z0-9+/=]{200,}$/)) {
      version = "Oracle 10g+ Wrap";
    } else if (input.includes("SHA-1") || input.length > 1000) {
      version = "Oracle 11g+ Wrap";
    }
    
    return { isWrapped: true, version };
  }
  
  return { isWrapped: false, version: null };
}

function cleanBase64(str) {
  // Remove everything except Base64 characters
  let cleaned = str.replace(/[^A-Za-z0-9+/=]/g, "");
  // Fix padding
  while (cleaned.length % 4) cleaned += "=";
  return cleaned;
}

function extractOracleWrapPatterns(input) {
  const lines = input.split('\n');
  const readable = [];
  let inString = false;
  let currentString = "";
  
  for (let line of lines) {
    // Look for quoted strings
    const stringMatches = line.match(/'[^']*'/g);
    if (stringMatches) {
      readable.push(...stringMatches.map(s => s.slice(1, -1)));
    }
    
    // Look for common PL/SQL keywords that might survive wrapping
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
  // Extract hex sequences
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
  // Extract only printable ASCII characters in sequences
  const matches = input.match(/[ -~]{5,}/g);
  if (!matches) return null;
  
  // Filter out pure Base64 looking strings
  const filtered = matches.filter(m => !m.match(/^[A-Za-z0-9+/=]+$/));
  
  return filtered.length > 0 ? filtered.join('\n') : null;
}

function isReadable(str) {
  // Check if string contains mostly readable characters
  const readable = str.replace(/[^\x20-\x7E\n\r\t]/g, "").length;
  return readable / str.length > 0.7;
}

function formatOutput(content, method) {
  return `/* ===== UnwrapPLSQL Analysis ===== */
/* Method: ${method} */
/* Timestamp: ${new Date().toLocaleString()} */
/* ================================= */

${content}

/* ===== End of Analysis ===== */
/* Note: Oracle wrap is one-way obfuscation. */
/* Recovered content may be partial. */`;
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
  const example = `CREATE OR REPLACE PACKAGE BODY "SAMPLE_PKG" wrapped 
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
dE7fG8hI9jK0lM1nO2pQ3rS4tU5vW6xY7zA8bC9dE0fG1hI2jK3lM4nO5pQ6rS7tU8vW9xY
0zA1bC2dE3fG4hI5jK6lM7nO8pQ9rS0tU1vW2xY3zA4bC5dE6fG7hI8jK9lM0nO1pQ2rS3tU
4vW5xY6zA7bC8dE9fG0hI1jK2lM3nO4pQ5rS6tU7vW8xY9zA0bC1dE2fG3hI4jK5lM6nO7pQ
8rS9tU0vW1xY2zA3bC4dE5fG6hI7jK8lM9nO0pQ1rS2tU3vW4xY5zA6bC7dE8fG9hI0jK1lM
2nO3pQ4rS5tU6vW7xY8zA9bC0dE1fG2hI3jK4lM5nO6pQ7rS8tU9vW0xY1zA2bC3dE4fG5hI6
/`;

  document.getElementById("input").value = example;
  analyze();
}

// Initialize theme
document.addEventListener('DOMContentLoaded', () => {
  // Prefer dark theme
  isDark = true;
});