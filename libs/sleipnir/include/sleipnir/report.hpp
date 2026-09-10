// Report generation: colored console summary + machine-readable JSON
// + standalone HTML report.
#pragma once

#include "sleipnir/results.hpp"
#include "sleipnir/types.hpp"

#include <string>

namespace sln {

void print_console_report(const ResultCollector& results,
                          const ScanConfig& cfg, double elapsed_seconds);

// Writes the JSON report; returns false on I/O failure.
bool write_json_report(const std::string& path,
                       const std::vector<PortResult>& ports,
                       const std::vector<Finding>& findings,
                       const ScanStats& stats, const ScanConfig& cfg,
                       double elapsed_seconds);

// Writes a self-contained HTML report (inline CSS, no external assets);
// returns false on I/O failure.
bool write_html_report(const std::string& path,
                       const std::vector<PortResult>& ports,
                       const std::vector<Finding>& findings,
                       const ScanStats& stats, const ScanConfig& cfg,
                       double elapsed_seconds);

// Dispatches on the --report file extension: .html/.htm -> HTML,
// otherwise JSON. Returns false on I/O failure.
bool write_report(const std::string& path,
                  const std::vector<PortResult>& ports,
                  const std::vector<Finding>& findings,
                  const ScanStats& stats, const ScanConfig& cfg,
                  double elapsed_seconds);

} // namespace sln
