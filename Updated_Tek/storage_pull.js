// Function to check if a string might contain sensitive data
function containsSensitiveData(str) {
  // Convert to string if not already
  const text = String(str).toLowerCase();
  
  // Patterns that might indicate sensitive data
  const sensitivePatterns = [
    /password/i, /passwd/i, /secret/i, /token/i, /jwt/i, /auth/i,
    /session/i, /ssn/i, /social.*security/i, /card/i, /credit/i,
    /debit/i, /account/i, /routing/i, /licens/i, /key/i,
    /cvv/i, /cvc/i, /expir/i, /bearer/i
  ];
  
  return sensitivePatterns.some(pattern => pattern.test(text));
}

// Function to download data as a text file
function downloadAsTextFile(data, filename) {
  const blob = new Blob([data], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  
  // Cleanup
  setTimeout(function() {
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, 0);
}

// Store all findings for saving to file later
const storageFindings = [];
const allCookies = [];

console.log("=== CHECKING BROWSER STORAGE FOR SENSITIVE DATA ===");

// 1. Check localStorage
console.log("\n--- LOCAL STORAGE ---");
storageFindings.push("--- LOCAL STORAGE ---");
for (let i = 0; i < localStorage.length; i++) {
  const key = localStorage.key(i);
  const value = localStorage.getItem(key);
  
  let logMessage = '';
  if (containsSensitiveData(key) || containsSensitiveData(value)) {
    logMessage = `⚠️ Potential sensitive data - ${key}: ${value}`;
  } else {
    logMessage = `${key}: ${value}`;
  }
  
  console.log(logMessage);
  storageFindings.push(logMessage);
}

// 2. Check sessionStorage
console.log("\n--- SESSION STORAGE ---");
storageFindings.push("\n--- SESSION STORAGE ---");
for (let i = 0; i < sessionStorage.length; i++) {
  const key = sessionStorage.key(i);
  const value = sessionStorage.getItem(key);
  
  let logMessage = '';
  if (containsSensitiveData(key) || containsSensitiveData(value)) {
    logMessage = `⚠️ Potential sensitive data - ${key}: ${value}`;
  } else {
    logMessage = `${key}: ${value}`;
  }
  
  console.log(logMessage);
  storageFindings.push(logMessage);
}

// 3. Check cookies
console.log("\n--- COOKIES ---");
storageFindings.push("\n--- COOKIES ---");
document.cookie.split(';').forEach(cookie => {
  if (!cookie.trim()) return; // Skip empty cookies
  
  const parts = cookie.trim().split('=');
  const key = parts[0];
  // Join the rest with '=' in case the value itself contains '='
  const value = parts.slice(1).join('=');
  
  // Add to consolidated cookie list
  allCookies.push(`${key}=${value}`);
  
  let logMessage = '';
  if (containsSensitiveData(key) || containsSensitiveData(value)) {
    logMessage = `⚠️ Potential sensitive data - ${key}: ${value}`;
  } else {
    logMessage = `${key}: ${value}`;
  }
  
  console.log(logMessage);
  storageFindings.push(logMessage);
});

// 4. Check URL for sensitive parameters
console.log("\n--- URL PARAMETERS ---");
storageFindings.push("\n--- URL PARAMETERS ---");
const urlParams = new URLSearchParams(window.location.search);
for (const [key, value] of urlParams.entries()) {
  let logMessage = '';
  if (containsSensitiveData(key) || containsSensitiveData(value)) {
    logMessage = `⚠️ Potential sensitive data - ${key}: ${value}`;
  } else {
    logMessage = `${key}: ${value}`;
  }
  
  console.log(logMessage);
  storageFindings.push(logMessage);
}

// 5. Check cache-related headers for current page
console.log("\n--- CACHE HEADERS ---");
storageFindings.push("\n--- CACHE HEADERS ---");

fetch(window.location.href, { method: 'HEAD' })
  .then(response => {
    const cacheControl = response.headers.get('Cache-Control');
    const expiresHeader = response.headers.get('Expires');
    const pragmaHeader = response.headers.get('Pragma');
    
    console.log('Cache-Control:', cacheControl);
    console.log('Expires:', expiresHeader);
    console.log('Pragma:', pragmaHeader);
    
    storageFindings.push(`Cache-Control: ${cacheControl}`);
    storageFindings.push(`Expires: ${expiresHeader}`);
    storageFindings.push(`Pragma: ${pragmaHeader}`);
    
    if (!cacheControl || 
        cacheControl.includes('public') || 
        !cacheControl.includes('no-store')) {
      const warning = '⚠️ This page may be improperly cached';
      console.warn(warning);
      storageFindings.push(warning);
    }
    
    // 6. Consolidated Cookie List
    console.log("\n--- CONSOLIDATED COOKIE LIST ---");
    if (allCookies.length > 0) {
      allCookies.forEach(cookie => console.log(cookie));
      
      // Create a downloadable file with just cookies
      const cookieText = allCookies.join('\n');
      downloadAsTextFile(cookieText, 'cookies_export.txt');
      console.log('Cookies exported to cookies_export.txt');
    } else {
      console.log('No cookies found');
    }
    
    // Create a downloadable file with all findings
    const reportText = storageFindings.join('\n');
    downloadAsTextFile(reportText, 'storage_report.txt');
    console.log('\nComplete findings exported to storage_report.txt');
    
    console.log("\n=== STORAGE CHECK COMPLETE ===");
    console.log("For more thorough cache analysis, please check the Network tab in Developer Tools");
  })
  .catch(err => {
    const errorMsg = `Error checking cache headers: ${err.message}`;
    console.error(errorMsg);
    storageFindings.push(errorMsg);
    
    // Still export cookies and findings even if cache check fails
    if (allCookies.length > 0) {
      const cookieText = allCookies.join('\n');
      downloadAsTextFile(cookieText, 'cookies_export.txt');
      console.log('Cookies exported to cookies_export.txt');
    }
    
    const reportText = storageFindings.join('\n');
    downloadAsTextFile(reportText, 'storage_report.txt');
    console.log('Complete findings exported to storage_report.txt');
  });
