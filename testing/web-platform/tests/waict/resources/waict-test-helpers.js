// Helper functions for WAICT tests

// Helper function to set up ReportingObserver for integrity violations
// Used by image tests (resources loaded in main document)
// For script tests, ReportingObserver is set up inside iframes
// Pass t (test object) if you want cleanup, omit for no cleanup (e.g., in iframes)
function setupIntegrityViolationObserver(t = null) {
  const reports = [];
  const observer = new ReportingObserver((reportList) => {
    reports.push(...reportList);
  }, {types: ['integrity-violation']});
  observer.observe();
  // Cleanup is needed for image tests to prevent observers from previous tests
  // interfering with subsequent tests. Not needed for iframes since they're
  // destroyed after each test.
  if (t && t.add_cleanup) {
    t.add_cleanup(() => observer.disconnect());
  }
  return reports;
}

// Here I expect that we will get some specific error
// For example, WAICTManifestURLParseError or WAICTHashMismatch
// I believe that it should be reflected in the reports
// IIUC, not it's not implemented so I don't check it.. 
function checkIntegrityViolationReport(reports, expectedURL, reportOnly, errorCode) {
  assert_greater_than(reports.length, 0, 'Should generate at least one integrity violation report');
  const report = reports[0];
  assert_equals(report.type, 'integrity-violation', 'Report type should be integrity-violation');
  assert_true(report.body.blockedURL.includes(expectedURL), 'Report should reference the blocked resource');
  assert_equals(report.body.reportOnly, reportOnly, reportOnly ? 'Report should be report-only' : 'Report should not be report-only');

  // Check error code if provided
  if (errorCode !== undefined) {
    assert_equals(report.body.errorCode, errorCode, 'Report should have the expected error code');
  }
}

async function loadScriptInIframe(iframeSrc, scriptSrc) {
  const iframe = document.createElement('iframe');
  iframe.src = iframeSrc;

  const readyPromise = new Promise(resolve => {
    window.addEventListener('message', function handler(event) {
      if (event.data.type === 'ready') {
        window.removeEventListener('message', handler);
        resolve();
      }
    });
  });

  document.body.appendChild(iframe);
  await readyPromise;

  // Request script load and wait for result
  const resultPromise = new Promise(resolve => {
    window.addEventListener('message', function handler(event) {
      if (event.data.type === 'scriptResult') {
        window.removeEventListener('message', handler);
        resolve(event.data);
      }
    });
  });

  iframe.contentWindow.postMessage({
    action: 'loadScript',
    src: scriptSrc
  }, '*');

  return await resultPromise;
}
