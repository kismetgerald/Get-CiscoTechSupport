# Performance Metrics - Test Results

This folder contains real-world performance test results for the Get-CiscoTechSupport installation and collection script.

---

## 📊 Available Reports

### Test 1: UNC Network Share Installation (v0.0.6)
**Date:** December 22, 2025
**Version:** 0.0.6
**Installation Source:** `\\NAS01\DataShare\Scripts\Install-GetCiscoTechSupport_v0.0.6`
**Installation Time:** 6m 42s
**Collection Time:** 2m 14s (3 devices)
**Total Time:** 8m 56s

- 📄 [Markdown Report](Air-Gapped_Lab_Test_20251222.md)

**Key Findings:**
- Archive extraction fallback (Expand-Archive) took 1m 20s due to UNC path incompatibility
- 100% collection success rate
- Email delivery in 775ms

---

### Test 2: Local Installation (v0.0.6)
**Date:** December 24, 2025
**Version:** 0.0.6
**Installation Source:** `C:\Temp\Install-GetCiscoTechSupport_v0.0.6`
**Installation Time:** 1m 32s
**Collection Time:** 2m 14s (3 devices)
**Total Time:** 3m 46s

- 📄 [Markdown Report](Local_Install_Test_20251224.md)

**Key Findings:**
- Archive extraction used fast .NET ZipFile method (8s)
- 100% collection success rate
- Email delivery in 732ms
- **77% faster installation** compared to UNC path (Test 1)

---

### Test 3: UNC Network Share Installation (v0.0.7)
**Date:** December 25, 2025
**Version:** 0.0.7 (with STIG wrapper logging)
**Installation Source:** `\\NAS01\DataShare\Scripts\Install-GetCiscoTechSupport_v0.0.7`
**Installation Time:** 2m 51s
**Collection Time:** 2m 13s (3 devices)
**STIG Execution:** 2m 37s (NEW in v0.0.7)
**Uninstallation:** 30s (NEW metric)
**Total Time:** 7m 41s

- 📄 [Markdown Report](Test3_UNC_Install_v0.0.7_20251225.md)

**Key Findings:**
- STIG wrapper logging feature adds comprehensive audit trail with zero performance penalty
- Archive extraction fallback (1m 20s) - same as Test 1
- 100% collection success rate
- Email delivery in 761ms
- First uninstallation metrics captured

---

### Test 4: Local Installation (v0.0.7) 🏆 FASTEST
**Date:** December 25, 2025
**Version:** 0.0.7 (with STIG wrapper logging)
**Installation Source:** `C:\Temp\Install-GetCiscoTechSupport_v0.0.7`
**Installation Time:** 1m 12s
**Collection Time:** 2m 15s (3 devices)
**STIG Execution:** 2m 19s (18s faster than Test 3)
**Uninstallation:** 26s (4s faster than Test 3)
**Total Time:** 5m 46s

- 📄 [Markdown Report](Test4_Local_Install_v0.0.7_20251225.md)

**Key Findings:**
- Fastest overall deployment: 5m 46s end-to-end
- Archive extraction (7s) - 10x faster than UNC
- 100% collection success rate
- Email delivery in 840ms
- **58% faster installation** compared to UNC path (Test 3)
- v0.0.7 wrapper logging with negligible overhead

---

### Performance Comparison (All 4 Tests)
**Comparison Date:** December 25, 2025
**Key Finding:** Local installation is **58-77% faster** than UNC network share

- 📄 [Markdown Report](Performance_Comparison.md)

**Highlights:**
- All 4 tests side-by-side comparison
- v0.0.6 vs v0.0.7 feature comparison
- UNC vs Local performance analysis
- New v0.0.7 metrics: STIG execution and uninstallation
- Production deployment recommendations

---

## 🎯 Quick Summary

| Metric | Test 1 (v0.0.6 UNC) | Test 2 (v0.0.6 Local) | Test 3 (v0.0.7 UNC) | Test 4 (v0.0.7 Local) 🏆 |
|--------|---------------------|----------------------|---------------------|-------------------------|
| **Version** | 0.0.6 | 0.0.6 | 0.0.7 | 0.0.7 |
| **Installation Time** | 6m 42s | 1m 32s | 2m 51s | **1m 12s** 🚀 |
| **Collection Time** | 2m 14s | 2m 14s | 2m 13s | 2m 15s |
| **Email Delivery** | 775ms | 732ms | 761ms | 840ms |
| **STIG Execution** | N/A | N/A | 2m 37s | 2m 19s |
| **Uninstallation** | N/A | N/A | 30s | 26s |
| **Total Time** | 8m 56s | 3m 46s | 7m 41s | **5m 46s** 🚀 |
| **Success Rate** | 100% | 100% | 100% | 100% |

**Key Takeaway:** Test 4 (v0.0.7 Local) is the fastest configuration with comprehensive logging features.

---

## 📁 Test Environment

All tests conducted on:
- **Host:** WIN11-03
- **OS:** Windows 11
- **PowerShell:** 5.1.26100
- **Python:** 3.14.1 (embedded)
- **Network:** Air-gapped lab environment
- **Devices:** 3 Cisco devices (same hardware, same devices)

---

## 🔍 How to View Reports

### Markdown Files (.md)
- Open in any text editor
- Best viewed in GitHub or VSCode with markdown preview
- Plain text format for easy searching/parsing

### HTML Files (.html)
- Open directly in any web browser (Chrome, Firefox, Edge, Safari)
- Professional styling with gradients, tables, and stat cards
- Performance Comparison includes bar chart visualizations
- Print-friendly CSS for PDF generation

---

## 💡 Key Recommendations

Based on all 4 test results:

1. **✅ Use v0.0.7 with local installation source (Test 4 configuration)**
   - Fastest deployment: 5m 46s end-to-end
   - Comprehensive STIG wrapper logging with zero performance penalty
   - Copy ZIP to local temp directory before installation
   - 58% faster than UNC installation

2. **✅ Use silent installation parameters**
   - Eliminate user-interactive delays (credential entry adds 38-48s)
   - Automate large-scale deployments
   - Expected time with silent install: ~30s installation

3. **✅ Leverage v0.0.7 features**
   - STIG execution logging provides comprehensive audit trail
   - Uninstallation metrics now tracked (26-30s complete removal)
   - Enhanced error reporting with exit code propagation

4. **✅ Optimize network shares (if UNC required)**
   - Enable SMB multichannel and SMB3
   - Expect 1m 39s installation penalty vs local (v0.0.7)
   - Archive extraction will use fallback method (1m 20s)

5. **📊 Collection and email performance is consistent**
   - Device collection times identical regardless of source/version (~2m 15s for 3 devices)
   - Email delivery consistently sub-second (732-840ms)
   - Performance determined by device complexity and network latency

---

## 🔄 Update History

- **2025-12-25:** Added Test 3 (v0.0.7 UNC) and Test 4 (v0.0.7 Local) with STIG wrapper logging metrics
- **2025-12-25:** Updated Performance Comparison with all 4 tests
- **2025-12-25:** Added new metrics: STIG execution time and uninstallation duration
- **2025-12-24:** Added Test 2 (v0.0.6 Local Installation) and initial Performance Comparison
- **2025-12-22:** Initial Test 1 (v0.0.6 UNC Network Share) results

---

## 📞 Using These Reports

These performance metrics can be used for:
- **Capacity planning** (estimating deployment times)
- **Infrastructure decisions** (local vs network share)
- **Executive summaries** (demonstrating script performance)
- **Wiki documentation** (real-world performance data)
- **Troubleshooting** (baseline performance expectations)

---

*Reports generated by Claude Code (Sonnet 4.5)*
*For issues or questions, see the main project README.md*
